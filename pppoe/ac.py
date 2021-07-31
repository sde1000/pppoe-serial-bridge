# PPPoE access concentrator implementation

# See RFC2516

import netifaces  # type: ignore
import struct
import selectors
import socket
from enum import Enum
import logging
import random
from typing import Generator, Dict, List, Tuple, Optional, NewType, Final

utf8: Final = "utf-8"

# Ethertypes
PPPOE_DISCOVERY: Final = 0x8863
PPPOE_SESSION: Final = 0x8864

# Constants for PPPoE headers
VERTYPE: Final = 0x11  # VER and TYPE combined into a single octet
CODE_PADI: Final = 0x09
CODE_PADO: Final = 0x07
CODE_PADR: Final = 0x19
CODE_PADS: Final = 0x65
CODE_PADT: Final = 0xa7

# Tag types
tts: Final[Dict[str, int]] = {
    'End-Of-List': 0x0000,
    'Service-Name': 0x0101,
    'AC-Name': 0x0102,
    'Host-Uniq': 0x0103,
    'AC-Cookie': 0x0104,
    'Vendor-Specific': 0x0105,
    'Relay-Session-Id': 0x0110,
    'Service-Name-Error': 0x0201,
    'AC-System-Error': 0x0202,
    'Generic-Error': 0x0203,
}


MacAddr = NewType('MacAddr', bytes)


def macaddr_to_str(m: MacAddr) -> str:
    return m.hex(":")


def str_to_macaddr(s: str) -> MacAddr:
    return MacAddr(bytes.fromhex(s.replace(':', '')))


broadcast: Final = str_to_macaddr('ff:ff:ff:ff:ff:ff')

# Discovery payloads contain zero or more tags. In some payloads, tags
# of the same type may be repeated.

# The order of tags in packets doesn't appear to be significant.

# Tag values of length 0 are permitted.

# Let's represent tags as a dict of tag type -> list of tag values,
# with the length of the list representing the number of tags of that
# type.

Tag = Tuple[int, bytes]
Tags = Dict[int, List[bytes]]

tag_header = struct.Struct("!HH")


def tag_to_payload(tag_type: int, value: bytes) -> bytes:
    return b''.join((tag_header.pack(tag_type, len(value)), value))


def tags_to_payload(tags: Tags) -> bytes:
    def flatten(tags: Tags) -> Generator[Tag, None, None]:
        for tag_type, values_list in tags.items():
            for value in values_list:
                yield (tag_type, value)
    return b''.join(tag_to_payload(tag_type, value)
                    for tag_type, value in flatten(tags))


def parse_payload(payload: memoryview) -> Generator[Tag, None, None]:
    # Parse the payload one tag at a time, yielding (tag_type, value)
    # Raise ValueError if payload isn't valid
    # Stop if tag type End-Of-List is encountered
    while len(payload) > 0:
        if len(payload) < tag_header.size:
            raise ValueError(f"Fewer than {tag_header.size} bytes available "
                             "in payload while parsing tag header")
        tag_type, value_size = tag_header.unpack(payload[:tag_header.size])
        payload = payload[tag_header.size:]
        if len(payload) < value_size:
            raise ValueError(f"Fewer than {value_size} bytes available "
                             "in payload while reading tag value")
        value = payload[:value_size].tobytes()
        payload = payload[value_size:]
        if tag_type == 0x0000:
            if value_size == 0:
                return
            raise ValueError("End-Of-List tag encountered with non-zero "
                             "tag length")
        yield tag_type, value


def payload_to_tags(payload: memoryview) -> Tags:
    # Convert payload to dict(tag_type: list of tag values)
    tags: Tags = {}
    for tag_type, value in parse_payload(payload):
        tags.setdefault(tag_type, list()).append(value)
    return tags


class ServiceState(Enum):
    IDLE = 1
    DIALING = 2
    CONNECTED = 3


class ServiceFailure(Exception):
    pass


class Service:
    # A service offered via an access concentrator. This base class
    # doesn't actually do anything: it never opens a device or
    # responds to PPP packets

    def __init__(self, log: logging.Logger, sel: selectors.BaseSelector,
                 name: str):
        self.log = log
        self.sel = sel
        self.name = name
        self.state: ServiceState = ServiceState.IDLE
        self.ac: Optional[AC] = None
        self.session_id: Optional[int] = None
        self.peer: Optional[MacAddr] = None

    def connect(self, ac: 'AC', peer: MacAddr,
                session_id: int) -> None:
        self.ac = ac
        self.session_id = session_id
        self.peer = peer
        self.state = ServiceState.CONNECTED

    def disconnect(self) -> None:
        self.ac = None
        self.session_id = None
        self.peer = None
        self.state = ServiceState.IDLE

    def process_session_payload(self, payload: bytes) -> None:
        pass

    def __str__(self) -> str:
        return f"Service(name={self.name}, state={self.state}, " \
            f"session_id={self.session_id})"


class AC:
    # An access concentrator
    eth_header = struct.Struct("!6s6sHBBHH")

    def __init__(self, log: logging.Logger, sel: selectors.BaseSelector,
                 interface: str, name: str, services: List[Service]):
        self.log = log
        self.name = name
        self.services = services
        # Find the MAC address of the interface
        addrs = netifaces.ifaddresses(interface)[netifaces.AF_PACKET]
        self.mac = str_to_macaddr(addrs[0]['addr'])

        # Buffer for receiving packets
        self.buf = bytearray(2048)
        self.buf_mem = memoryview(self.buf)

        # Open the interface and bind to the discovery and session ethertypes
        self.s_discovery = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                         socket.htons(PPPOE_DISCOVERY))
        self.s_discovery.bind((interface, 0))
        self.s_discovery.setblocking(False)
        sel.register(
            self.s_discovery, selectors.EVENT_READ, self.read_discovery)
        self.s_session = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(PPPOE_SESSION))
        self.s_session.bind((interface, 0))
        self.s_session.setblocking(False)
        sel.register(self.s_session, selectors.EVENT_READ, self.read_session)

        self.sessions: Dict[int, Service] = {}
        self.session_number = self._session_number_generator()
        # MTU of the interface; read with SIOCGIFMTU?
        self.mtu = 1500

    def _session_number_generator(self) -> Generator[int, None, None]:
        """Generate valid unused session numbers
        """
        i = random.randint(0x0001, 0xffff)
        while True:
            if i not in self.sessions:
                yield i
            i += 1
            if i > 0xffff:
                i = 0x0001

    def read_discovery(self, mask: int) -> None:
        framesize = self.s_discovery.recv_into(self.buf)
        if framesize < self.eth_header.size:
            return
        dest, src, etype, vt, code, session_id, payload_length \
            = self.eth_header.unpack_from(self.buf)
        dest = MacAddr(dest)
        src = MacAddr(src)
        if etype != PPPOE_DISCOVERY:
            self.log.debug("Discovery packet with incorrect ethertype")
            return
        if vt != VERTYPE:
            self.log.debug("Discovery packet with unknown ver/type")
            return
        payload = self.buf_mem[self.eth_header.size:]
        if len(payload) < payload_length:
            self.log.debug("payload in discovery frame is shorter than "
                           "declared length")
            return
        payload = payload[:payload_length]
        try:
            tags = payload_to_tags(payload)
        except ValueError:
            self.log.debug("invalid tags in discovery packet payload")
            return
        if code == CODE_PADI:
            if session_id != 0x0000:
                self.log.debug("PADI with non-zero session ID")
                return
            self.handle_padi(src, tags)
        elif code == CODE_PADR:
            if dest != self.mac:
                self.log.debug("PADR with incorrect destination address")
                return
            if session_id != 0x0000:
                self.log.debug("PADR with non-zero session ID")
                return
            self.handle_padr(src, tags)
        elif code == CODE_PADT:
            if session_id == 0x0000:
                self.log.debug("PADT with zero session ID")
                return
            self.handle_padt(src, session_id, tags)

    def send_discovery(self, peer: MacAddr, code: int,
                       session_id: int = 0x0000,
                       tags: Tags = {}) -> None:
        payload = tags_to_payload(tags)
        frame = b''.join((self.eth_header.pack(
            peer, self.mac, PPPOE_DISCOVERY, VERTYPE, code,
            session_id, len(payload)), payload))
        self.s_discovery.send(frame)

    def handle_padi(self, peer: MacAddr, tags: Tags) -> None:
        self.log.debug("PADI from %s with tags %r", macaddr_to_str(peer), tags)
        # Check that there is exactly one Service-Name tag
        if tts['Service-Name'] not in tags:
            self.log.debug("Received PADI with no Service-Name tag")
            return
        sns = tags[tts['Service-Name']]
        if len(sns) != 1:
            self.log.debug("Received PADI with %d Service-Name tags", len(sns))
            return
        try:
            requested_service = sns[0].decode(utf8)
        except UnicodeDecodeError:
            self.log.debug("Invalid Unicode in PADI Service-Name tag")
            return
        available_services = {x.name for x in self.services}
        if not requested_service or requested_service in available_services:
            # Wildcard request, or requested service is available; send reply
            rtags = {
                tts['Service-Name']: [
                    x.encode(utf8) for x in available_services],
                tts['AC-Name']: [self.name.encode(utf8)],
            }
            # Copy tags from request
            for ct in ('Host-Uniq', 'Relay-Session-Id'):
                if tts[ct] in tags:
                    rtags[tts[ct]] = tags[tts[ct]]
            self.send_discovery(peer, CODE_PADO, tags=rtags)

    def handle_padr(self, peer: MacAddr, tags: Tags) -> None:
        self.log.debug("PADR from %s with tags %r", macaddr_to_str(peer), tags)
        # Maybe establish a session and send a PADS
        if tts['Service-Name'] not in tags:
            self.log.debug("Received PADR with no Service-Name tag")
            return
        sns = tags[tts['Service-Name']]
        if len(sns) != 1:
            self.log.debug("Received PADR with %d Service-Name tags", len(sns))
            return
        try:
            requested_service = sns[0].decode(utf8)
        except UnicodeDecodeError:
            self.log.debug("Invalid Unicode in PADI Service-Name tag")
            return
        if requested_service:
            # Filter service list by service name
            services = [x for x in self.services
                        if x.name == requested_service]
        else:
            services = list(self.services)

        # If the services list is empty, the requested service name is invalid
        if not services:
            rtags = {
                tts['Service-Name-Error']:
                ["Requested service does not exist".encode(utf8)],
            }
            # Copy tags from request
            for ct in ('Host-Uniq', 'Relay-Session-Id'):
                if tts[ct] in tags:
                    rtags[tts[ct]] = tags[tts[ct]]
            self.send_discovery(peer, CODE_PADS, tags=rtags)
            return
        # Pick an idle service; if there are none, pick the one with
        # the greatest idle time and terminate it (on the grounds that
        # it's not in active use)
        # XXX TODO; for now, just use the first one
        service = services[0]

        # We're going to be sending a PADS; start to
        # prepare the tags
        rtags = {
            tts['Service-Name']: [service.name.encode(utf8)],
        }
        # Copy tags from request
        for ct in ('Host-Uniq', 'Relay-Session-Id'):
            if tts[ct] in tags:
                rtags[tts[ct]] = tags[tts[ct]]

        if service.state != ServiceState.IDLE:
            assert service.session_id and service.peer
            # Send a PADT for the existing connection
            self.log.info("Service %s session %s: sending PADT to close "
                          "existing session", service, hex(service.session_id))
            self.send_discovery(service.peer, CODE_PADT,
                                session_id=service.session_id)
            del self.sessions[service.session_id]
            service.disconnect()
        session_id = next(self.session_number)
        try:
            service.connect(self, peer, session_id)
        except ServiceFailure as sf:
            self.log.warning("Service %s failed to connect: %s", service.name,
                             sf)
            # Service failed immediately: send PADS with AC-System-Error
            rtags[tts['AC-System-Error']] = [str(sf).encode(utf8)]
            self.send_discovery(peer, CODE_PADS, tags=rtags)
            return

        # Session is now valid
        self.log.info("Service %s connected to %s with session id %s",
                      service.name, macaddr_to_str(peer), hex(session_id))
        self.sessions[session_id] = service
        self.send_discovery(peer, CODE_PADS, session_id=session_id, tags=rtags)

    def handle_padt(self, peer: MacAddr, session_id: int, tags: Tags) -> None:
        # Maybe terminate a session. No reply.
        if session_id in self.sessions:
            self.log.info(
                "Recieved PADT for session %s: disconnecting service %s",
                hex(session_id), self.sessions[session_id].name)
            self.sessions[session_id].disconnect()
            del self.sessions[session_id]
        else:
            self.log.debug(
                "Received PADT for unknown session %s", hex(session_id))

    def read_session(self, mask: int) -> None:
        framelen = self.s_session.recv_into(self.buf)
        if framelen < self.eth_header.size:
            return
        dest, src, etype, vt, code, session_id, payload_length \
            = self.eth_header.unpack_from(self.buf)
        dest = MacAddr(dest)
        src = MacAddr(src)
        if etype != PPPOE_SESSION:
            self.log.debug("Session packet with incorrect ethertype")
            return
        if vt != VERTYPE:
            self.log.debug("Session packet with unknown ver/type")
            return
        if code != 0:
            self.log.debug("Session packet with non-zero code")
            return
        payload = self.buf_mem[self.eth_header.size:]
        if len(payload) < payload_length:
            self.log.debug("payload in session frame is shorter than "
                           "declared length")
            return
        payload = payload[:payload_length]
        if session_id in self.sessions:
            self.sessions[session_id].process_session_payload(payload.tobytes())
        else:
            self.log.info("Sending PADT to %s for unknown session %s",
                          macaddr_to_str(src), hex(session_id))
            self.send_discovery(src, CODE_PADT, session_id=session_id)

    def send_session(self, peer: MacAddr, session_id: int,
                     payload: bytes) -> None:
        if len(payload) > self.mtu:
            return
        frame = b''.join((self.eth_header.pack(
            peer, self.mac, PPPOE_SESSION, VERTYPE, 0,
            session_id, len(payload)), payload))
        self.s_session.send(frame)

    def close_session(self, peer: MacAddr, session_id: int,
                      error_message: Optional[str] = None) -> None:
        # The session is being closed by the service: possibly the
        # modem was unplugged, for example
        if session_id in self.sessions:
            del self.sessions[session_id]
        tags: Tags = {}
        if error_message:
            tags[tts['AC-System-Error']] = [error_message.encode(utf8)]

        self.send_discovery(peer, CODE_PADT, session_id=session_id, tags=tags)

    def shutdown(self, message: str) -> None:
        for session_id, service in list(self.sessions.items()):
            if not service.peer or not service.session_id:
                continue
            self.close_session(
                service.peer, session_id, error_message=message)
