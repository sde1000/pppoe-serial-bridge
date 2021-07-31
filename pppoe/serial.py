# Service that implements PPP framing according to RFC1662

from .ac import MacAddr, Service, ServiceFailure, AC
import subprocess
import serial  # type: ignore
import os
import logging
import selectors
from typing import Final, Generator, Optional, Callable

ppp_flag_byte: Final = 0x7e
ppp_escape_code: Final = 0x7d
ppp_hdlc_header: Final = bytes.fromhex('ff 03')
ppp_bytes_to_stuff: Final = {ppp_flag_byte, ppp_escape_code}


# Algorithm from RFC1662 appendix C
def _gen_fcs16tab() -> Generator[int, None, None]:
    for b in range(0, 0x100):
        for _ in range(8):
            b = (b >> 1) ^ 0x8408 if b & 1 else (b >> 1)
        yield b


ppp_fcs16tab: Final = tuple(_gen_fcs16tab())

FCS16_INIT: Final = 0xffff
FCS16_GOOD: Final = 0xf0b8


class ppp_stuff:
    """Take raw ppp frames from pppoe payloads and process for serial

    Frame, checksum and bytestuff raw frames for transmission to the
    modem
    """
    def __init__(self, buf: memoryview):
        self.buf = buf

    def process(self, input: memoryview) -> int:
        i = 0
        fcs = FCS16_INIT
        buf = self.buf

        def stuff(b: int) -> None:
            nonlocal i
            if b in ppp_bytes_to_stuff:
                buf[i] = ppp_escape_code
                i += 1
                buf[i] = b ^ 0x20
                i += 1
            else:
                buf[i] = b
                i += 1

        def fcs16(b: int) -> None:
            nonlocal fcs
            fcs = (fcs >> 8) ^ ppp_fcs16tab[(fcs ^ b) & 0xff]

        buf[i] = ppp_flag_byte
        i += 1
        for b in ppp_hdlc_header:
            fcs16(b)
            stuff(b)
        for b in input:
            fcs16(b)
            stuff(b)
        fcs = fcs ^ FCS16_INIT
        for b in (fcs & 0xff, fcs >> 8):
            stuff(b)
        buf[i] = ppp_flag_byte
        i += 1
        return i


class ppp_unstuff:
    """Take data from the modem and process into raw ppp frames

    Raw frames are assembled into output_memory, and send_frame() is
    called whenever a complete frame is present
    """
    def __init__(self, output_memory: memoryview,
                 send_frame: Callable[[int], None],
                 log: logging.Logger):
        self.in_frame = False
        self.out = output_memory
        self.send_frame = send_frame
        self.log = log

    def start_new_frame(self) -> None:
        self.in_frame = True
        self.hdlc_header_bytes_checked = 0
        self.in_escape = False
        self.frame_size = 0
        self.fcs = FCS16_INIT

    def process_byte(self, b: int) -> None:
        if self.in_frame:
            if b == ppp_flag_byte:
                if self.in_escape:
                    # This is illegal; dump the frame
                    self.log.debug("Frame from modem ended with escape code")
                    self.in_frame = False
                    return
                # We've reached the end of the frame. Send it if it's
                # legal!
                if self.frame_size < 4:
                    # Empty frame; ignore
                    pass
                else:
                    if self.fcs == FCS16_GOOD:
                        self.send_frame(self.frame_size - 2)
                    else:
                        self.log.debug("Invalid FCS received from modem, "
                                       "fcs=%s, len=%d",
                                       hex(self.fcs), self.frame_size)
                self.start_new_frame()
                return
            if self.in_escape:
                b = b ^ 0x20
                self.in_escape = False
            else:
                if b == ppp_escape_code:
                    self.in_escape = True
                    return
            self.fcs = (self.fcs >> 8) ^ ppp_fcs16tab[(self.fcs ^ b) & 0xff]
            if self.hdlc_header_bytes_checked < len(ppp_hdlc_header):
                if b == ppp_hdlc_header[self.hdlc_header_bytes_checked]:
                    self.hdlc_header_bytes_checked += 1
                else:
                    self.log.debug("Bad frame header from modem")
                    self.in_frame = False
                return
            if self.frame_size >= len(self.out):
                self.log.debug("Frame from modem is too long")
                self.in_frame = False
            else:
                self.out[self.frame_size] = b
                self.frame_size += 1
        else:
            if b == ppp_flag_byte:
                self.start_new_frame()

    def process(self, data: bytes) -> None:
        for i in data:
            self.process_byte(i)


class SerialService(Service):
    def __init__(self, log: logging.Logger, sel: selectors.BaseSelector,
                 name: str, port: str, chatscript: Optional[str] = None):
        super().__init__(log, sel, name)
        self.port = port
        self.chatscript = chatscript
        self._f: Optional[serial.Serial] = None
        # Buffer and memory view for traffic from ethernet to the modem
        self.outbuf = bytearray(4096)
        self.outbuf_memory = memoryview(self.outbuf)
        # Buffer for frame being prepared for sending to ethernet
        self.inbuf = bytearray(2048)
        self.inbuf_memory: Optional[memoryview] = None

    def connect(self, ac: AC, peer: MacAddr, session_id: int) -> None:
        super().connect(ac, peer, session_id)
        try:
            self._f = serial.Serial(self.port, timeout=0.0, write_timeout=0.0)
        except serial.SerialException as s:
            super().disconnect()
            raise ServiceFailure(f"Failed to open modem on {self.port}: {s}")
        # Read and throw away from the fd: there may be a "NO CARRIER"
        # message buffered from a previous connection that would cause
        # a chatscript to fail
        self._f.read(1024)
        self.sel.register(self._f, selectors.EVENT_READ, self.read_from_modem)
        if self.chatscript:
            os.set_blocking(self._f.fileno(), True)
            rc = subprocess.run(
                ["/usr/sbin/chat", "-v", "-f", self.chatscript],
                stdin=self._f, stdout=self._f)
            os.set_blocking(self._f.fileno(), False)
            if rc.returncode != 0:
                self.disconnect()
                raise ServiceFailure(
                    f"Chatscript failed with return code {rc.returncode}")
        self.ppp_stuff = ppp_stuff(self.outbuf_memory)
        self.ppp_unstuff = ppp_unstuff(
            ac.prepare_send_session(self.inbuf), self.send_frame, self.log)

    def disconnect(self) -> None:
        super().disconnect()
        del self.ppp_stuff, self.ppp_unstuff
        if self._f:
            self.sel.unregister(self._f)
            self._f.close()
        self._f = None

    def process_session_payload(self, payload: memoryview) -> None:
        assert self._f
        size = self.ppp_stuff.process(payload)
        # serial.Serial.write() appears to busy-wait until it can
        # write to the device, which is particularly unhelpful because
        # it pegs the CPU at 100%. Let's use os.write() on the fd
        # instead.
        try:
            os.write(self._f.fileno(), self.outbuf_memory[:size])
        except BlockingIOError:
            # Should we keep a statistics counter for this?
            pass

    def read_from_modem(self, mask: int) -> None:
        # The behaviour of serial.Serial.read() is very unhelpful when
        # the device has been disconnected: it raises SerialException
        # when os.read() returns no data, and then raises _another_
        # SerialException while internally handling the first one,
        # which we can't catch here.
        #
        # Let's call os.read() on the fd ourselves and save a whole
        # lot of trouble!
        #
        # A serial.Serial.readinto() would be lovely, but it's
        # currently implemented with an internal serial.Serial.read()
        # and yet another copy and also has the exception issue
        # described above.
        #
        # (os.readinto() would be lovely too, but doesn't exist. Grr.)

        assert self._f and self.ac and self.peer and self.session_id
        rawdata = os.read(self._f.fileno(), 4096)
        if not rawdata:
            self.log.error(f"Service {self.name}: could not read from modem; "
                           f"closing session {hex(self.session_id)}")
            self.ac.close_session(self.peer, self.session_id,
                                  error_message="Modem disconnected")
            self.disconnect()
            return
        self.ppp_unstuff.process(rawdata)

    def send_frame(self, frame_size: int) -> None:
        # Callback from ppp_unstuff
        assert self.ac and self.peer and self.session_id and self.inbuf
        self.ac.send_session(self.peer, self.session_id,
                             self.inbuf, frame_size)
