cimport cython

cdef unsigned char ppp_flag_byte = 0x7e
cdef unsigned char ppp_escape_code = 0x7d
cdef ppp_bytes_to_stuff = {0x7d, 0x7e}
cdef unsigned char[2] ppp_hdlc_header = [0xff, 0x03]

cdef unsigned short FCS16_INIT = 0xffff
cdef unsigned short FCS16_GOOD = 0xf0b8

cdef unsigned short ppp_fcs16tab[0x100]

# Algorithm from RFC1662 appendix C
for i in range(0, 0x100):
    b = i
    for _ in range(8):
        b = (b >> 1) ^ 0x8408 if b & 1 else (b >> 1)
    ppp_fcs16tab[i] = b

cdef inline unsigned short fcs16(unsigned short fcs, unsigned short data):
    return (fcs >> 8) ^ ppp_fcs16tab[(fcs ^ data) & 0xff]

@cython.final
cdef class ppp_stuff:
    cdef int i
    cdef unsigned short fcs
    cdef unsigned char [:] buf

    def __init__(self, output: memoryview):
        self.buf = output

    @cython.final
    cdef inline void stuff(self, unsigned char b):
        if b == 0x7d or b == 0x7e:
            self.buf[self.i] = ppp_escape_code; self.i += 1
            self.buf[self.i] = b ^ 0x20; self.i += 1
        else:
            self.buf[self.i] = b; self.i += 1

    @cython.final
    cdef inline void add_fcs(self, unsigned char b):
        self.fcs = fcs16(self.fcs, b)
        self.stuff(b)

    def process(self, input: memoryview):
        cdef unsigned char [:] payload = input
        cdef int x = 0
        self.i = 0
        self.fcs = FCS16_INIT
        self.buf[self.i] = ppp_flag_byte
        self.i += 1
        self.add_fcs(0xff)
        self.add_fcs(0x03)
        while x < payload.size:
            self.add_fcs(payload[x])
            x += 1
        self.fcs = self.fcs ^ FCS16_INIT
        self.stuff(self.fcs & 0xff)
        self.stuff(self.fcs >> 8)
        self.buf[self.i] = ppp_flag_byte
        self.i += 1
        return self.i

@cython.final
cdef class ppp_unstuff:
    cdef bint in_frame
    cdef unsigned int hdlc_header_bytes_checked
    cdef bint in_escape
    cdef unsigned int in_frame_size
    cdef unsigned short in_fcs
    cdef unsigned char [:] out
    cdef send_frame
    cdef log

    def __init__(self, output_memory: memoryview, send_frame, log):
        self.in_frame = False
        self.out = output_memory
        self.send_frame = send_frame
        self.log = log

    @cython.final
    cdef inline void start_new_frame(self):
        self.in_frame = True
        self.hdlc_header_bytes_checked = 0
        self.in_escape = False
        self.in_frame_size = 0
        self.in_fcs = FCS16_INIT

    @cython.final
    cdef inline void process_byte(self, unsigned char b):
        if self.in_frame:
            if b == ppp_flag_byte:
                if self.in_escape:
                    # This is illegal; dump the frame
                    self.log.debug("Frame from modem ended with escape code")
                    self.in_frame = False
                    return
                # We've reached the end of the frame. Send it if it's
                # legal!
                if self.in_frame_size < 4:
                    # Empty frame; ignore
                    pass
                else:
                    if self.in_fcs == FCS16_GOOD:
                        self.send_frame(self.in_frame_size - 2)
                    else:
                        self.log.debug("Invalid FCS received from modem, fcs=%s, len=%d", hex(self.in_fcs), self.in_frame_size)
                self.start_new_frame()
                return
            if self.in_escape:
                b = b ^ 0x20
                self.in_escape = False
            else:
                if b == ppp_escape_code:
                    self.in_escape = True
                    return
            self.in_fcs = fcs16(self.in_fcs, b)
            if self.hdlc_header_bytes_checked < len(ppp_hdlc_header):
                if b == ppp_hdlc_header[self.hdlc_header_bytes_checked]:
                    self.hdlc_header_bytes_checked += 1
                else:
                    self.log.debug("Bad frame header from modem")
                    self.in_frame = False
                return
            if self.in_frame_size >= len(self.out):
                self.log.debug("Frame from modem is too long")
                self.in_frame = False
            else:
                self.out[self.in_frame_size] = b
                self.in_frame_size += 1
        else:
            if b == ppp_flag_byte:
                self.start_new_frame()

    def process(self, data: bytes):
        cdef const unsigned char [:] inbuf = data
        cdef unsigned int i = 0
        while i < len(inbuf):
            self.process_byte(inbuf[i])
            i += 1

