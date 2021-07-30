# Service that implements PPP framing according to RFC1662

from .ac import MacAddr, Service, ServiceFailure, AC
import subprocess
import serial  # type: ignore
import os
import logging
import selectors
from typing import Final, Generator, Optional

ppp_flag_sequence: Final = bytes.fromhex('7e')
ppp_hdlc_header: Final = bytes.fromhex('ff 03')
ppp_bytes_to_stuff: Final = {0x7d, 0x7e}


# Algorithm from RFC1662 appendix C
def _gen_fcs16tab() -> Generator[int, None, None]:
    for b in range(0, 0x100):
        for _ in range(8):
            b = (b >> 1) ^ 0x8408 if b & 1 else (b >> 1)
        yield b


ppp_fcs16tab: Final = tuple(_gen_fcs16tab())


def fcs16(data: bytes) -> bytes:
    fcs = 0xffff
    for b in data:
        fcs = (fcs >> 8) ^ ppp_fcs16tab[(fcs ^ b) & 0xff]
    fcs = fcs ^ 0xffff
    return bytes((fcs & 0xff, fcs >> 8))


def ppp_stuff(data: bytes) -> Generator[int, None, None]:
    i = iter(data)
    try:
        while True:
            b = next(i)
            if b in ppp_bytes_to_stuff:
                yield 0x7d
                yield b ^ 0x20
            else:
                yield b
    except StopIteration:
        pass


def ppp_unstuff(data: bytes) -> Generator[int, None, None]:
    i = iter(data)
    try:
        while True:
            b = next(i)
            if b == 0x7d:
                b = next(i) ^ 0x20
            yield b
    except StopIteration:
        pass


class SerialService(Service):
    def __init__(self, log: logging.Logger, sel: selectors.BaseSelector,
                 name: str, port: str, chatscript: Optional[str] = None):
        super().__init__(log, sel, name)
        self.port = port
        self.chatscript = chatscript
        self._f: Optional[serial.Serial] = None

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
        self._partial_frame: Optional[bytes] = None

    def disconnect(self) -> None:
        super().disconnect()
        if self._f:
            self.sel.unregister(self._f)
            self._f.close()
        self._f = None

    def process_session_payload(self, payload: bytes) -> None:
        assert self._f
        frame = ppp_hdlc_header + payload
        frame = frame + fcs16(frame)
        frame = bytes(ppp_stuff(frame))
        frame = ppp_flag_sequence + frame + ppp_flag_sequence
        # serial.Serial.write() appears to busy-wait until it can
        # write to the device, which is particularly unhelpful because
        # it pegs the CPU at 100%. Let's use os.write() on the fd
        # instead.
        try:
            os.write(self._f.fileno(), frame)
        except BlockingIOError:
            # Should we keep a statistics counter for this?
            pass

    def read_from_modem(self, mask: int) -> None:
        # The behaviour of serial.Serial.read() is very unhelpful when
        # the device has been disconnected: it raises SerialException
        # when os.read() returns no data, and then raises _another_
        # SerialException while handling the first one, which we can't
        # catch here.
        #
        # Let's call os.read() on the fd ourselves and save a whole
        # lot of trouble!
        assert self._f and self.ac and self.peer and self.session_id
        rawdata = os.read(self._f.fileno(), 4096)
        if not rawdata:
            self.log.error(f"Service {self.name}: could not read from modem; "
                           f"closing session {hex(self.session_id)}")
            self.ac.close_session(self.peer, self.session_id,
                                  error_message="Modem disconnected")
            self.disconnect()
            return
        data = rawdata.split(ppp_flag_sequence)

        # If self._partial_frame is None, we have not yet received a
        # flag sequence and so should discard the first segment
        if self._partial_frame is None:
            data.pop(0)
            if data:
                self._partial_frame = b''
            else:
                return  # No more data to process, still no flag sequence

        # If there is a partial frame stored from a previous read, add
        # it on to the first segment of data.
        data[0] = self._partial_frame + data[0]

        # If there is any data in the last segment it may be a partial
        # frame, because the data we read didn't end with a flag
        # sequence.  Remove and store the last segment for the next
        # read.
        self._partial_frame = data.pop(-1)

        # Any segments containing data should be ppp frames
        for s in data:
            if len(s) > 0:
                self.process_frame_from_modem(s)

    def process_frame_from_modem(self, frame: bytes) -> None:
        frame = bytes(ppp_unstuff(frame))
        fcs = fcs16(frame[:-2])
        if fcs != frame[-2:]:
            self.log.warning("FCS error: frame=%s", frame.hex())
            return
        if frame[:2] != ppp_hdlc_header:
            self.log.warning("HDLC header not as expected: frame=%s",
                             frame.hex())
            return
        assert self.ac and self.peer and self.session_id
        self.ac.send_session(self.peer, self.session_id, frame[2:-2])
