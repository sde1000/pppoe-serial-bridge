#!/usr/bin/env python3

# PPPoE to serial PPP bridge

# See RFC1662 for ppp serial framing
# See RFC2516 for PPPoE

import argparse
import pppoe.ac
import pppoe.serial
import selectors
import logging
from typing import List

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Bridge serial ppp to ethernet")
    parser.add_argument('--ac-name',
                        default="pppoe-serial-bridge",
                        help="name of access concentrator")
    parser.add_argument('--chatscript', metavar="FILENAME",
                        default=None, help="path to chatscript")
    parser.add_argument('serial_device', metavar='serial-device',
                        help="path to serial device")
    parser.add_argument('service_name', metavar='service-name',
                        help="name of service")
    parser.add_argument('interface', help="ethernet interface")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('pppoe-serial')

    sel = selectors.DefaultSelector()
    services: List[pppoe.ac.Service] = [
        pppoe.serial.SerialService(log, sel, args.service_name,
                                   args.serial_device, args.chatscript),
        # Service(log, sel, "null"),
    ]
    acs = [pppoe.ac.AC(log, sel, args.interface, args.ac_name, services)]

    try:
        while True:
            events = sel.select()
            for key, mask in events:
                key.data(mask)
    finally:
        # Send PADT for all known sessions
        for ac in acs:
            ac.shutdown("Shutting down")
