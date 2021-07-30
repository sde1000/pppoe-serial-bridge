# Service that implements PPP framing according to RFC1662

from .ac import MacAddr, Service, ServiceFailure, AC
from . import ppp_hdlc  # type: ignore
import subprocess
import serial  # type: ignore
import os
import logging
import selectors
from typing import Optional


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
        self.ppp_stuff = ppp_hdlc.ppp_stuff(self.outbuf_memory)
        self.ppp_unstuff = ppp_hdlc.ppp_unstuff(
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
