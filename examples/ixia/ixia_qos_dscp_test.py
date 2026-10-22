#!/usr/bin/env python
"""Ixia traffic profile to test QoS (DSCP) markings through a DUT.

Builds one IPv4 traffic item per QoS class between two 100G ports, each
transmitted with its own DSCP value. Egress tracking on the receive port
records the DSCP value actually received, so the script can verify that the
DUT either preserved or re-marked each class as expected, and reports per-class
loss.

    Tx port --> [ DUT ] --> Rx port

Requires ixnetwork_restpy (pip install ixnetwork_restpy).

Example:
    python ixia_qos_dscp_test.py --api-server 10.1.1.10 --chassis 10.1.1.20 \
        --tx-port 1/1 --rx-port 1/2 --duration 30

Classes can be overridden with a JSON file passed to --classes, e.g.:
    [
        {"name": "EF",   "dscp": 46, "expected_dscp": 46, "rate": 10},
        {"name": "AF41", "dscp": 34, "expected_dscp": 34, "rate": 20},
        {"name": "BE",   "dscp": 0,  "expected_dscp": 0,  "rate": 30}
    ]
"rate" is percent of line rate; "expected_dscp" defaults to "dscp".
"""

from __future__ import print_function, unicode_literals

import argparse
import json
import os
import sys
import time
from getpass import getpass

from ixnetwork_restpy import SessionAssistant

from ixia_100g_connect import set_100g

# Default profile: common enterprise/SP QoS classes. Total = 70% of line rate.
DEFAULT_CLASSES = [
    {"name": "EF", "dscp": 46, "rate": 10},
    {"name": "CS6", "dscp": 48, "rate": 5},
    {"name": "AF41", "dscp": 34, "rate": 15},
    {"name": "AF31", "dscp": 26, "rate": 15},
    {"name": "AF21", "dscp": 18, "rate": 10},
    {"name": "BE", "dscp": 0, "rate": 15},
]

EGRESS_VIEW_NAME = "QoS DSCP Egress"
# Ethernet header (14 bytes) + IPv4 version/IHL (1 byte) = 120 bits to the DSCP
# field on an untagged frame. Add 32 bits per 802.1Q tag on the receive port.
DSCP_OFFSET_BITS = 120
DSCP_WIDTH_BITS = 6


def parse_args():
    parser = argparse.ArgumentParser(description="Ixia QoS DSCP marking test")
    parser.add_argument("--api-server", required=True, help="IxNetwork API server IP")
    parser.add_argument("--rest-port", type=int, default=443, help="REST port")
    parser.add_argument("--username", default="admin", help="API server username")
    parser.add_argument("--chassis", required=True, help="Ixia chassis IP")
    parser.add_argument("--tx-port", default="1/1", help="Transmit card/port")
    parser.add_argument("--rx-port", default="1/2", help="Receive card/port")
    parser.add_argument("--tx-ip", default="10.0.1.2", help="Tx port IPv4 address")
    parser.add_argument("--tx-gw", default="10.0.1.1", help="Tx port gateway (DUT)")
    parser.add_argument("--rx-ip", default="10.0.2.2", help="Rx port IPv4 address")
    parser.add_argument("--rx-gw", default="10.0.2.1", help="Rx port gateway (DUT)")
    parser.add_argument("--prefix", type=int, default=24, help="IPv4 prefix length")
    parser.add_argument("--classes", help="JSON file describing the QoS classes")
    parser.add_argument("--frame-size", type=int, default=512, help="Frame size")
    parser.add_argument("--duration", type=int, default=30, help="Seconds of traffic")
    parser.add_argument(
        "--max-loss", type=float, default=0.0, help="Allowed loss %% per class"
    )
    parser.add_argument(
        "--rx-vlan-tags",
        type=int,
        default=0,
        help="Number of 802.1Q tags on frames received by the Rx port",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        help="Leave the IxNetwork session and port ownership in place on exit",
    )
    return parser.parse_args()


def load_classes(path):
    classes = DEFAULT_CLASSES
    if path:
        with open(path) as f:
            classes = json.load(f)
    for qos_class in classes:
        qos_class.setdefault("expected_dscp", qos_class["dscp"])
    total_rate = sum(c["rate"] for c in classes)
    if total_rate > 100:
        raise ValueError("Total rate {}% exceeds line rate".format(total_rate))
    return classes


def split_port(card_port):
    card, port = card_port.split("/")
    return int(card), int(port)


def build_topology(ixnetwork, vport, name, ip, gateway, prefix):
    topology = ixnetwork.Topology.add(Name=name, Ports=vport)
    device_group = topology.DeviceGroup.add(Name=name + "_DG", Multiplier=1)
    ethernet = device_group.Ethernet.add(Name=name + "_Eth")
    ipv4 = ethernet.Ipv4.add(Name=name + "_IPv4")
    ipv4.Address.Single(ip)
    ipv4.GatewayIp.Single(gateway)
    ipv4.Prefix.Single(prefix)
    return ipv4


def build_traffic_items(ixnetwork, src, dst, classes, frame_size, duration):
    """Create one traffic item per QoS class, marked with that class's DSCP."""
    for qos_class in classes:
        traffic_item = ixnetwork.Traffic.TrafficItem.add(
            Name="QoS_{}".format(qos_class["name"]), TrafficType="ipv4"
        )
        traffic_item.EndpointSet.add(Sources=src, Destinations=dst)
        config_element = traffic_item.ConfigElement.find()[0]
        config_element.FrameRate.update(Type="percentLineRate", Rate=qos_class["rate"])
        config_element.FrameSize.FixedSize = frame_size
        config_element.TransmissionControl.update(
            Type="fixedDuration", Duration=duration
        )

        # The "Default PHB" field carries the full 6-bit DSCP value
        ipv4_stack = config_element.Stack.find(StackTypeId="^ipv4$")
        dscp_field = ipv4_stack.Field.find(DisplayName="^Default PHB$")
        dscp_field.ActiveFieldChoice = True
        dscp_field.ValueType = "singleValue"
        dscp_field.SingleValue = qos_class["dscp"]

        traffic_item.Tracking.find()[0].TrackBy = ["trafficItem"]
        traffic_item.Generate()


def enable_dscp_egress_tracking(ixnetwork, offset_bits):
    """Track the received DSCP on every traffic item."""
    ixnetwork.Traffic.Apply()
    for traffic_item in ixnetwork.Traffic.TrafficItem.find():
        egress = traffic_item.Tracking.find()[0].Egress
        egress.Encapsulation = "Any: Use Custom Settings"
        egress.CustomOffsetBits = offset_bits
        egress.CustomWidthBits = DSCP_WIDTH_BITS
        traffic_item.EgressEnabled = True
        traffic_item.Generate()
    ixnetwork.Traffic.Apply()


def create_egress_view(ixnetwork):
    """Create a flow view showing rx frames per traffic item per received DSCP."""
    ixnetwork.Statistics.View.add(
        Caption=EGRESS_VIEW_NAME,
        TreeViewNodeName="Egress Custom Views",
        Type="layer23TrafficFlow",
        Visible=True,
    )
    view = ixnetwork.Statistics.View.find(Caption=EGRESS_VIEW_NAME)

    flow_filter = view.Layer23TrafficFlowFilter.find()[0]
    flow_filter.EgressLatencyBinDisplayOption = "showEgressRows"
    flow_filter.PortFilterIds = [f.href for f in view.AvailablePortFilter.find()]
    flow_filter.TrafficItemFilterIds = [
        f.href for f in view.AvailableTrafficItemFilter.find()
    ]

    egress_filter = None
    ingress_filter = None
    for tracking_filter in view.AvailableTrackingFilter.find():
        if tracking_filter.Name.startswith("Custom:"):
            egress_filter = tracking_filter.href
        elif tracking_filter.Name == "Traffic Item":
            ingress_filter = tracking_filter.href
    if egress_filter is None:
        raise RuntimeError("Egress DSCP tracking filter not found")

    if ingress_filter is not None:
        flow_filter.EnumerationFilter.add(
            SortDirection="ascending", TrackingFilterId=ingress_filter
        )
    flow_filter.EnumerationFilter.add(
        SortDirection="ascending", TrackingFilterId=egress_filter
    )

    for statistic in view.Statistic.find():
        statistic.Enabled = True
    view.Enabled = True


def wait_for_traffic_stop(ixnetwork, timeout):
    """Fixed-duration traffic stops on its own; wait for it and for stats to settle."""
    traffic = ixnetwork.Traffic
    deadline = time.time() + timeout
    while True:
        traffic.refresh()
        if traffic.State == "stopped":
            break
        if time.time() > deadline:
            traffic.StopStatelessTrafficBlocking()
            raise RuntimeError("Traffic did not stop within {}s".format(timeout))
        time.sleep(2)
    time.sleep(5)


def to_int(value):
    """Parse a stat cell as an integer (decimal or 0x hex); None if empty."""
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def get_received_dscp(session):
    """Return {traffic item name: {received dscp: rx frames}} from the egress view."""
    rows = session.StatViewAssistant(EGRESS_VIEW_NAME).Rows
    columns = rows.Columns
    egress_col = next(i for i, c in enumerate(columns) if c.startswith("Custom:"))
    item_col = columns.index("Traffic Item")
    rx_col = columns.index("Rx Frames")

    received = {}
    traffic_item = None
    for row in rows.RawData:
        # Egress sub-rows may leave the ingress (traffic item) column blank
        traffic_item = row[item_col] or traffic_item
        dscp = to_int(row[egress_col])
        rx_frames = to_int(row[rx_col]) or 0
        if traffic_item is None or dscp is None or rx_frames == 0:
            continue
        by_dscp = received.setdefault(traffic_item, {})
        by_dscp[dscp] = by_dscp.get(dscp, 0) + rx_frames
    return received


def check_results(session, classes, max_loss):
    item_stats = session.StatViewAssistant("Traffic Item Statistics")
    print(item_stats)
    loss_by_item = {}
    for row in item_stats.Rows:
        loss_by_item[row["Traffic Item"]] = float(row["Loss %"] or 0)

    received = get_received_dscp(session)

    print(
        "\n{:<8} {:>6} {:>9} {:>8}  {}".format(
            "Class", "Tx", "Expected", "Loss %", "Received DSCP (frames)"
        )
    )
    failures = []
    for qos_class in classes:
        item_name = "QoS_{}".format(qos_class["name"])
        loss = loss_by_item.get(item_name)
        rx_dscp = received.get(item_name, {})
        print(
            "{:<8} {:>6} {:>9} {:>8}  {}".format(
                qos_class["name"],
                qos_class["dscp"],
                qos_class["expected_dscp"],
                "n/a" if loss is None else "{:.3f}".format(loss),
                ", ".join("{}:{}".format(d, f) for d, f in sorted(rx_dscp.items()))
                or "none",
            )
        )

        if loss is None or loss > max_loss:
            failures.append("{}: loss {}% > {}%".format(item_name, loss, max_loss))
        wrong = {d: f for d, f in rx_dscp.items() if d != qos_class["expected_dscp"]}
        if not rx_dscp:
            failures.append("{}: no egress DSCP data received".format(item_name))
        elif wrong:
            failures.append(
                "{}: expected DSCP {}, also received {}".format(
                    item_name, qos_class["expected_dscp"], wrong
                )
            )

    if failures:
        print("\nFAIL")
        for failure in failures:
            print("  " + failure)
        return 1
    print(
        "\nPASS: all classes received with expected DSCP and loss <= {}%".format(
            max_loss
        )
    )
    return 0


def main():
    args = parse_args()
    classes = load_classes(args.classes)
    password = os.environ.get("IXIA_PASSWORD") or getpass("API server password: ")

    session = SessionAssistant(
        IpAddress=args.api_server,
        RestPort=args.rest_port,
        UserName=args.username,
        Password=password,
        ClearConfig=True,
        LogLevel=SessionAssistant.LOGLEVEL_INFO,
    )
    ixnetwork = session.Ixnetwork

    try:
        port_map = session.PortMapAssistant()
        tx_card, tx_port = split_port(args.tx_port)
        rx_card, rx_port = split_port(args.rx_port)
        tx_vport = port_map.Map(args.chassis, tx_card, tx_port, Name="Tx")
        rx_vport = port_map.Map(args.chassis, rx_card, rx_port, Name="Rx")
        port_map.Connect(ForceOwnership=True)
        set_100g(tx_vport)
        set_100g(rx_vport)

        tx_ipv4 = build_topology(
            ixnetwork, tx_vport, "Tx", args.tx_ip, args.tx_gw, args.prefix
        )
        rx_ipv4 = build_topology(
            ixnetwork, rx_vport, "Rx", args.rx_ip, args.rx_gw, args.prefix
        )

        ixnetwork.StartAllProtocols(Arg1="sync")
        protocols = session.StatViewAssistant("Protocols Summary")
        protocols.CheckCondition("Sessions Not Started", protocols.EQUAL, 0)
        protocols.CheckCondition("Sessions Down", protocols.EQUAL, 0)

        build_traffic_items(
            ixnetwork, tx_ipv4, rx_ipv4, classes, args.frame_size, args.duration
        )
        enable_dscp_egress_tracking(
            ixnetwork, DSCP_OFFSET_BITS + 32 * args.rx_vlan_tags
        )
        create_egress_view(ixnetwork)

        print("Running traffic for {} seconds...".format(args.duration))
        ixnetwork.Traffic.StartStatelessTrafficBlocking()
        wait_for_traffic_stop(ixnetwork, args.duration + 60)

        return check_results(session, classes, args.max_loss)
    finally:
        if not args.keep_session:
            ixnetwork.Vport.find().ReleasePort()
            session.Session.remove()


if __name__ == "__main__":
    sys.exit(main())
