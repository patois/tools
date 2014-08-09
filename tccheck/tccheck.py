#!/usr/bin/python

# Truecrypt integrity checker for whole-disc-encrypted volumes
# tested on Truecrypt 7.1a

import os, sys, hashlib

class TCSectors(object):   
    def __init__(self, desc, startsec, numsec, sizehasharea, knownhashes):
        self.desc = desc
        self.startsec = startsec
        self.numsec = numsec
        self.sizehasharea = sizehasharea
        self.knownhashes = knownhashes
        self.raw_data = None
        self.realhash = None
        self.isknownhash = False

    def set_raw_data(self, data):
        self.raw_data = data
        self.realhash = hashlib.sha256(self.raw_data[:self.sizehasharea]).hexdigest()
        self.isknownhash = self.realhash in self.knownhashes

    def is_known(self):
        return self.isknownhash

    def get_raw_data(self):
        return self.raw_data

    def get_desc(self):
        return self.desc

    def get_hash(self):
        return self.realhash

    def dump_to_disc(self, path):
        try:
            f = open(path, "wb")
            f.write(self.raw_data)
            f.close()
            return True
        except:
            return False

class TCFS(object):

    SIZE_SECTOR = 0x200

    DESC_BOOTSECTOR = "bootsector.bin"
    SECTOR_BOOTSECTOR = 1
    NUM_SECTORS_BOOTSECTOR = 1
    SIZE_BOOTSECTOR_HASH  = 438
    BOOTSECTOR_HASHES = ["ec574ce4a0ba33636821ab32e76e471718d6929b539f7179320b4c520cddd371"]

    DESC_DECOMPRESSOR = "decompressor.bin"
    SECTOR_DECOMPRESSOR = 2
    NUM_SECTORS_DECOMPRESSOR = 4
    SIZE_DECOMPRESSOR_HASH = NUM_SECTORS_DECOMPRESSOR * SIZE_SECTOR
    DECOMPRESSOR_HASHES = ["0d0e31752933a6d469988df3019258a00c80ae7bfbaee965492e180ac19b0d96"]

    DESC_BOOTLOADER = "bootloader.gz"
    SECTOR_BOOTLOADER = 6
    NUM_SECTORS_BOOTLOADER = 0x39
    SIZE_BOOTLOADER_HASH = NUM_SECTORS_BOOTLOADER * SIZE_SECTOR
    BOOTLOADER_HASHES = ["0c4e21cbe737d5545baec21e6515692796dde9f6d66be8b783c3f5dd3c99c839"]

    DESC_BACKUPBOOTLOADER = "backupBootloader.gz"
    SECTOR_BACKUPBOOTLOADER = 0x24
    NUM_SECTORS_BACKUPBOOTLOADER = 0x1A
    SIZE_BACKUPBOOTLOADER_HASH = NUM_SECTORS_BACKUPBOOTLOADER * SIZE_SECTOR
    BACKUPBOOTLOADER_HASHES = ["343e70dbd48e2c8fc80313c9ad37ce757be53fee8b00a3ff43fd62524e83ccab"]

    def __init__(self):
        self.f = None
        self.tc_mbr_sectors = []
        self.tc_mbr_sectors.append( \
            TCSectors(self.DESC_BOOTSECTOR, \
                      self.SECTOR_BOOTSECTOR, \
                      self.NUM_SECTORS_BOOTSECTOR, \
                      self.SIZE_BOOTSECTOR_HASH, \
                      self.BOOTSECTOR_HASHES))
        
        self.tc_mbr_sectors.append( \
            TCSectors(self.DESC_DECOMPRESSOR, \
                      self.SECTOR_DECOMPRESSOR, \
                      self.NUM_SECTORS_DECOMPRESSOR, \
                      self.SIZE_DECOMPRESSOR_HASH, \
                      self.DECOMPRESSOR_HASHES))
        
        self.tc_mbr_sectors.append(\
            TCSectors(self.DESC_BOOTLOADER, \
                      self.SECTOR_BOOTLOADER, \
                      self.NUM_SECTORS_BOOTLOADER, \
                      self.SIZE_BOOTLOADER_HASH, \
                      self.BOOTLOADER_HASHES))
        
        self.tc_mbr_sectors.append( \
            TCSectors(self.DESC_BACKUPBOOTLOADER, \
                      self.SECTOR_BACKUPBOOTLOADER, \
                      self.NUM_SECTORS_BACKUPBOOTLOADER, \
                      self.SIZE_BACKUPBOOTLOADER_HASH, \
                      self.BACKUPBOOTLOADER_HASHES))      

    def open(self, dev, mode="rb"):
        result = False
        try:
            self.f = open(dev, mode)
            result = True
        except:
            self.f = None
            
        return result

    def close(self):
        if self.f:
            self.f.close()
            self.f = None

    def read_raw_sectors(self, sector, numsectors):
        result = (False, "Invalid sector %d" % sector)
        if sector > 0:
            try:
                self.f.seek((sector-1) * self.SIZE_SECTOR)
                buf = self.f.read(numsectors * self.SIZE_SECTOR)
                result = (True, buf)
            except:
                result = (False, "Could not read %d sector(s) starting at sector %d" % (numsectors, sector))
        return result

    def read_mbr_sector_area(self, mbrsec):
        b, res = self.read_raw_sectors(mbrsec.startsec, mbrsec.numsec)
        if b:
            mbrsec.set_raw_data(res[:mbrsec.sizehasharea])
        return b

    def read_mbr_sectors(self):
        for mbrsec in self.tc_mbr_sectors:
            self.read_mbr_sector_area(mbrsec)
       
    def MBRSectors(self):
        self.read_mbr_sectors()
        for s in self.tc_mbr_sectors:
            yield s

def usage():
    print "Usage:\n%s <device> [path]" % sys.argv[0]
    exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    dev = sys.argv[1]
    path = sys.argv[2] if len(sys.argv) > 2 else None
    errors = []
    
    fs = TCFS()
    if not fs.open(dev):
        print "Error, '%s' could not be opened." % dev
        exit(0)
   
    for mbrsec in fs.MBRSectors():
        desc = mbrsec.get_desc()
        known = mbrsec.is_known()
        print("* %s: %s" % (desc, "OK" if known else "UNKNOWN!"))
        if not known:
            errors.append("! %s: hash failure (unknown or compromised TrueCrypt version!\n  %s)" % (desc, mbrsec.get_hash()))
        if path:
            if not mbrsec.dump_to_disc(os.path.join(path, desc)):
                errors.append("! %s could not be written." % desc)

    fs.close()
    
    if errors:
        print "\nErrors:"
        for err in errors:
            print err
    print "\ndone."

    
