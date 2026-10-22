#!/usr/bin/env python
"""Connect to a 100G port on an Ixia (Keysight) chassis.

Ixia test ports are not CLI devices, so Netmiko cannot drive them. This script
uses the IxNetwork REST API (ixnetwork_restpy) instead:

    pip install ixnetwork_restpy

Example:
    python ixia_100g_connect.py --api-server 10.1.1.10 --chassis 10.1.1.20 \
        --card 1 --port 1
"""

from __future__ import print_function, unicode_literals

import argparse
import os
import sys
from getpass import getpass

from ixnetwork_restpy import SessionAssistant

SPEED_100G = "speed100g"
SPEED_100G_MBPS = 100000


def parse_args():
    parser = argparse.ArgumentParser(description="Connect to an Ixia 100G port")
    parser.add_argument("--api-server", required=True, help="IxNetwork API server IP")
    parser.add_argument("--rest-port", type=int, default=443, help="REST port")
    parser.add_argument("--chassis", required=True, help="Ixia chassis IP")
    parser.add_argument("--card", type=int, default=1, help="Card/slot number")
    parser.add_argument("--port", type=int, default=1, help="Port number")
    parser.add_argument("--username", default="admin", help="API server username")
    parser.add_argument("--name", default="Port_100G", help="Virtual port name")
    parser.add_argument(
        "--link-timeout", type=int, default=120, help="Seconds to wait for link up"
    )
    parser.add_argument(
        "--ignore-link-up",
        action="store_true",
        help="Do not fail if the link does not come up (e.g. no cable)",
    )
    parser.add_argument(
        "--keep-session",
        action="store_true",
        help="Leave the IxNetwork session and port ownership in place on exit",
    )
    return parser.parse_args()


def set_100g(vport):
    """Set the port speed to 100G if the card's L1 type exposes a speed setting."""
    l1_config = vport.L1Config
    current_type = l1_config.CurrentType
    print("L1 type: {}".format(current_type))

    # e.g. "novusHundredGigLan" -> l1_config.NovusHundredGigLan
    l1_attr = current_type[0].upper() + current_type[1:]
    l1_type = getattr(l1_config, l1_attr, None)
    if l1_type is None or not hasattr(l1_type, "Speed"):
        print("L1 type has no configurable speed; leaving it as-is")
        return
    if l1_type.Speed != SPEED_100G:
        print("Changing speed from {} to {}".format(l1_type.Speed, SPEED_100G))
        l1_type.Speed = SPEED_100G


def main():
    args = parse_args()
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
        vport = port_map.Map(
            IpAddress=args.chassis, CardId=args.card, PortId=args.port, Name=args.name
        )
        port_map.Connect(
            ForceOwnership=True,
            LinkUpTimeout=args.link_timeout,
            IgnoreLinkUp=args.ignore_link_up,
        )

        set_100g(vport)
        vport.refresh()

        print("Port:         {}".format(vport.AssignedTo))
        print("Connection:   {}".format(vport.ConnectionStatus))
        print("Link state:   {}".format(vport.State))
        print("Actual speed: {} Mbps".format(vport.ActualSpeed))

        if vport.State == "up" and int(vport.ActualSpeed or 0) != SPEED_100G_MBPS:
            print("WARNING: link is up but not running at 100G", file=sys.stderr)
            return 1
        return 0
    finally:
        if not args.keep_session:
            # Release the port and remove the session from the API server
            ixnetwork.Vport.find().ReleasePort()
            session.Session.remove()


if __name__ == "__main__":
    sys.exit(main())
