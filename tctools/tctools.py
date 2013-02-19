import sys, os, hashlib, struct, random

class tcinfo:
    def __init__(self, \
                 verstring, \
                 brdecoderarea, \
                 brencode, \
                 tcusercfgflags, \
                 ):
        self.verstring = verstring
        self.brdecoderarea = brdecoderarea
        self.brencode = brencode
        self.tcusercfgflags = tcusercfgflags


class tctools:
    def __init__(self):
        random.seed()
        self.f = None
        self.bootrecord = None
        self.brencoder = []
        self.instructions = []
        self.sig = None
        self.encodedbr = None
        
        # TrueCrypt v7.0a
        tc70awin = tcinfo( \
            verstring = "7.0a win", \
            brdecoderarea = (0, 0x1E), \
            brencode = (0x1E, 0x1A0), \
            tcusercfgflags = (0x1B6, 1),
            )

        # dictionary of supported TrueCrypt versions
        self.tcversions = {
            "6e5a8c97707eeeb673e2fd8886e2a23f":tc70awin
            }

    def EnableSilentMode(self, brinfo):
        flagsoffs, flagslen = brinfo.tcusercfgflags
        self.bootrecord = self.bootrecord[0:flagsoffs] + \
                          chr(ord(self.bootrecord[flagsoffs:flagsoffs+1]) | 0x1) + \
                          self.bootrecord[flagsoffs+1:]
        

    def OpenDevice(self, device, mode):
        result = False
        if not self.f:
            try:
                self.f = open(device, mode)
                result = True
            except IOError:
                pass
        return result

    def CloseDevice(self):
        if self.f:
            self.f.close()

    def CloseDevice(self):
        self.f.close()
        
    def ReadSector(self, num=0):
        self.f.seek(num * 0x200)
        return self.f.read(0x200)

    def ReadMBR(self):
        result = False
        buf = self.ReadSector()
        if len(buf) == 0x200:
            self.bootrecord = buf
            result = True
        return result

    def GetBootCodeHash(self):
        digest = None
        if self.bootrecord:
            buf = self.bootrecord[0:0x190]
            m = hashlib.md5()
            m.update(buf)
            digest = m.hexdigest()
        return digest

    def GetBootRecordInfo(self):
        info = None
        md5hash = self.GetBootCodeHash()
        if md5hash in self.tcversions:
            info = self.tcversions[md5hash]
        return info

    def BuildNewBR(self, brinfo=None, shuffle=True):
        result = True
        errors = []
        
        if brinfo:
            # mov cx, brencode.len
            initcounter = "\xB9" + struct.pack("<H", brinfo.brencode[1])

            # xor ax, ac
            # mov ds, ax
            initds = "\x31\xC0" + \
                     "\x8E\xD8"

            # mov si, brencode.addr
            # mov di, si
            initsidi = "\xBE" + struct.pack("<H", 0x7C00+brinfo.brencode[0]) + \
                       "\x89\xF7"

            # cld
            initdf = "\xFC"

            # lodsb
            getbyte = "\xAC"

            algo = ""
            for ins in self.instructions:
                opc, op = ins
                if len(op) == 2:
                    if opc == "xor":
                        if op == "cl":
                            # xor al, cl
                            algo += "\x30\xC8"
                        else:
                            # xor al, num
                            algo += "\x34" + chr(int(op, 0x10))
                            
                    elif opc == "add":
                        if op == "cl":
                            # add al, cl
                            algo += "\x00\xC8"
                        else:
                            # add al, num
                            algo += "\x04" + chr(int(op, 0x10))

                    elif opc == "rol":
                        if op == "cl":
                            # rol al, cl
                            algo += "\xD2\xC0"
                        else:
                            # rol al, num
                            algo += "\x0C\x0C" + chr(int(op, 0x10))
            # stosb
            putbyte = "\xAA"

            # calc relative jmp delta for loop instruction
            reljmp = 0 - (2 + len(getbyte) + len(algo) + len(putbyte)) & 0xFF

            # handle fwd jmp
            if reljmp <= 0x7F:
                result = False
                errors.append("encoder too long")

            # loop
            loop = "\xE2" + struct.pack("B", reljmp)

            # build encoder
            decoderinit = [initcounter, initds, initsidi, initdf]
            decoderloop = [getbyte + algo + putbyte + loop]
            
            if shuffle:
                for i in xrange(len(decoderinit)):
                    pos = random.randint(0, len(decoderinit))
                    decoderinit.insert(pos, decoderinit.pop(i))
            decoder = decoderinit + decoderloop

            # calc length of decoder
            decoderlen = 0
            for gadget in decoder:
                decoderlen += len(gadget)

            maxdecoderlen = brinfo.brdecoderarea[1]

            if self.sig:
                if (len (self.sig) < 0x7F) and (decoderlen + len(self.sig) + 2 <= maxdecoderlen):
                    decoder = ["\xEB" + chr(len(self.sig)) + self.sig] + decoder
                    decoderlen += len(self.sig) + 2
                else:
                    # handle error
                    result = False
                    errors.append("signature too long")

            # fill remaining space with nops
            while decoderlen < maxdecoderlen:
                 if shuffle:
                     pos = random.randint(0, len(decoder))
                 else:
                     pos = len(encoder)
                 decoder.insert(pos, "\x90")
                 decoderlen += 1                                    

            if result:
                self.brdecoder = ""
                for code in decoder:
                    self.brdecoder += code
                encoffs, enclen = brinfo.brencode
                self.EnableSilentMode(brinfo)
                self.encodedbr = self.EncodeBuffer(brinfo, self.bootrecord[encoffs:encoffs+enclen], self.instructions)                
        return (result, errors)

    def Xor8(self, buf, num, runlen=False):
        newbuf = ""
        cl = num
        for c in buf:
            newbuf += chr((ord(c) ^ (cl & 0xFF)) & 0xFF)
            if runlen:
                cl -= 1
        return newbuf

    def Sub8(self, buf, num, runlen=False):
        newbuf = ""
        cl = num
        for c in buf:
            newbuf += chr((ord(c) - (cl & 0xFF)) & 0xFF)
            if runlen:
                cl -= 1
        return newbuf

    def Ror8(self, buf, num, runlen=False):
        newbuf = ""
        cl = num
        for c in buf:
            cl %= 8
            newbuf += chr( ((ord(c) >> (cl & 0xFF)) | (ord(c) << (8 - (cl & 0xFF)))) & 0xFF)
            if runlen:
                cl -= 1
        return newbuf


    def EncodeBuffer(self, brinfo, buf, instructions):
        newbuf = buf
        for i in xrange(len(instructions)):
            ins = instructions.pop()
            opc, op = ins
            rl = False
            encode = None
            if len(op) == 2:
                if opc == "xor":
                    if op == "cl":
                        # xor al, cl
                        encode = self.Xor8
                        val = brinfo.brencode[1]
                        rl = True
                    else:
                        # xor al, num
                        encode = self.Xor8
                        val = int(op, 0x10)
                        
                elif opc == "add":
                    if op == "cl":
                        # add al, cl
                        encode = self.Sub8
                        val = brinfo.brencode[1]
                        rl = True
                    else:
                        # add al, num
                        encode = self.Sub8
                        val = int(op, 0x10)

                elif opc == "rol":
                    if op == "cl":
                        # rol al, cl
                        encode = self.Ror8
                        val = brinfo.brencode[1]
                        rl = True
                    else:
                        # rol al, num
                        encode = self.Ror8
                        val = int(op, 0x10)
                        
                newbuf = encode(newbuf, val, rl)
        return newbuf

    def WriteNewBR(self, brinfo):
        decoffs, declen = brinfo.brdecoderarea
        encoffs, enclen = brinfo.brencode

        self.f.seek(decoffs)
        self.f.write(self.brdecoder)

        self.f.seek(encoffs)
        self.f.write(self.encodedbr)       

    def SetBRInstructions(self, instructions=[]):
        self.instructions = instructions

    def SetBRSignature(self, sig):
        self.sig = sig

def usage():
    print "\nusage: %s <device>\n" \
          "    device can be a physical device such as\n" \
          "    '\\\\.\\PhysicalDrive0' or an image/virtual disc\n" \
          "    such as 'Windows XP Professional.vmdk'.\n" % os.path.basename(sys.argv[0])

if len(sys.argv) < 2:
    usage()
    sys.exit(0)


tc = tctools()
tcdev = sys.argv[1]

if not tc.OpenDevice(tcDev, "rb+"):
    print "error: could not open device"
    sys.exit(0)
else:
    if tc.ReadMBR():
        info = tc.GetBootRecordInfo()
        if info:
            print "TrueCrypt v%s" % info.verstring
            
            tc.SetBRInstructions([("rol","cl"), ("xor","60"), ("add","cl")])
            tc.SetBRSignature("NTLDR")        
            success, errors = tc.BuildNewBR(info, shuffle=True)

            if success:
                print "new bootrecord successfully built."
                if raw_input("Write to '%s' now? Type 'YES' to continue. " % tcDev) == "YES":
                    tc.WriteNewBR(info)
                    print "done."
            else:
                for err in errors:
                    print "error: %s" % err
        else:
            print "No supported bootrecord detected!"
    tc.CloseDevice()
