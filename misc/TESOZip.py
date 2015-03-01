import zipfile
from zipfile import _ZipDecrypter
import zlib
import struct
import sys
import os
import elfesteem.pe_init
#from elfesteem.pe_init import PE
import StringIO

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

class TESOZip:
    def __init__(self, filename, outdir="out/", multi = False):
        self.filename = filename
        self.outdir = outdir
        self.filesize = os.path.getsize(self.filename)
        self.multi = multi
        if open(filename, "rb").read(2) == "\x4D\x5A":
            self.buf = open(filename, "rb").read()
            self.pe = elfesteem.pe_init.PE(self.buf)
            if self.pe.isPE() == True:
                f = self.RmPE()
                if f == None:
                    self.zp = None
                self.zp = zipfile.ZipFile(f)
        else:
            self.zp = zipfile.ZipFile(self.filename)

    def RmPE(self):
        overlap_off = self.pe.SHList[self.pe.Coffhdr.numberofsections - 1].offset + self.pe.SHList[self.pe.Coffhdr.numberofsections - 1].size
        if self.filesize > overlap_off:
            if self.pe.NThdr.optentries[4].rva != 0:  # 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
                self.buf = self.buf[overlap_off:self.pe.NThdr.optentries[4].rva]
            else:
                self.buf = self.buf[overlap_off:]
            f = StringIO.StringIO(self.buf)
            return f
        return None

    def PrintInfos(self):
        for info in self.zp.infolist():
            print "[+] info.filename        = %s" % info.filename
            print "[+] info.compress_type   = %X" % info.compress_type
            print "[+] info.comment         = %s" % info.comment
            #print "[+] info.extra           = %s" % info.extra
            print "[+] info.create_system   = %X" % info.create_system
            print "[+] info.create_version  = %X" % info.create_version
            print "[+] info.extract_version = %X" % info.extract_version
            print "[+] info.reserved        = %X" % info.reserved
            print "[+] info.flag_bits       = %X" % info.flag_bits
            if info.flag_bits & 0x1:
                print "[+] ENCRYPTED!"
            print "[+] info.volume          = %X" % info.volume
            print "[+] info.internal_attr   = %X" % info.internal_attr
            print "[+] info.external_attr   = %X" % info.external_attr
            print "-" * 20

    def ExtractFile(self, filename):
        if not os.path.exists(self.outdir):
            os.mkdir(self.outdir)
        for info in self.zp.infolist():
            if info.filename != filename:
                continue
            if self.multi == True:
                fd = open(self.filename.replace("zip", "z01"), "rb")
                buf = self.ExtractData(fd, info)
            else:
                buf = self.ExtractData(self.zp.fp, info)
            if len(buf) > 0:
                if len(os.path.dirname(filename)) > 0:
                    if not os.path.exists(self.outdir + os.path.dirname(filename)):
                        os.makedirs(self.outdir + os.path.dirname(filename))
                open(self.outdir + filename, "wb").write(buf)
                return True
        return False

    def ExtractData(self, fd, info):
        offset = info.header_offset
        fd.seek(offset)
        sig = struct.unpack("<H", fd.read(2))[0]
        if sig != 0x4B50:
            fd.seek(offset - 8)
            sig = struct.unpack("<H", fd.read(2))[0]
            if sig != 0x4B50:
                print "FU!"
                sys.exit(42)
            offset = offset - 8
        fd.seek(offset + 26)
        file_name_len, extra_len = struct.unpack("<HH", fd.read(4))
        file_name = fd.read(file_name_len)
        if file_name != info.filename:
            print "[-] there is something wrong!"
            return ""
        fd.seek(offset + 30 + file_name_len + extra_len)
        buf = fd.read(info.compress_size)
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        if info.flag_bits & 0x1: # ENCRYPTED
            password = self.ExtractPassword(info.extra)
            zd = _ZipDecrypter(password)
            buf = ''.join(zd(c) for c in buf)
            buf_u = decoder.decompress(buf[0xC:])
        else:
            buf_u = decoder.decompress(buf)
        return buf_u

    def ExtractPassword(self, extra):
        flag, length = struct.unpack("<HH", extra[0:4])
        if flag != 0x8810:
            print "[-] extract_passw - wrong flag!"
            sys.exit(42)
        if length > 0x78:
            length = 0x78
        passw = self.ComputePassword(extra[4:4 + length])
        return passw

    def ComputePassword(self, passw):
        out = ""
        passw += "\x00" * (0x78 - len(passw))
        for i in xrange(0, len(passw)):
            if ord(passw[i]) == 0:
                break
            v = 8
            j = (ord(passw[0x77]) ^ (ord(passw[i]) + ((1 << (i % 0x20)) & 0xFF)))
            while v > 0 and j > 0x7E:
                j = (j & (~(1 << v))) & 0xFF
                v = v - 1
            if j < 0x21:
                j = (j | (1 << ((j % 3) + 5))) + 1
            out += chr(j)
        return out



#def extract_comp_file(filename, offset, length, outdir="out/"):
#    fd = open(filename, "rb")
#    fd.seek(offset)
#    sig = struct.unpack("<H", fd.read(2))[0]
#    if sig != 0x4B50:
#        fd.seek(offset - 8)
#        sig = struct.unpack("<H", fd.read(2))[0]
#        if sig != 0x4B50:
#            print "FU!"
#            sys.exit(42)
#        offset = offset - 8
#    fd.seek(offset + 26)
#    file_name_len, extra_len = struct.unpack("<HH", fd.read(4))
#    file_name = fd.read(file_name_len)
#    print file_name
#    flag, mm = struct.unpack("<HH", fd.read(4))
#    #print "[+] flag: %04X" % flag
#    fd.seek(offset + 30 + file_name_len + extra_len)
#    buf = fd.read(length)
#    #print hexdump(buf[:0x50])
#    #print "-" * 10
#    #print hexdump(buf[0x0D:0x20])
#    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
#    buf_u = decoder.decompress(buf)
#    #buf_u = zlib.decompress(buf[0xC:])
#    if len(os.path.dirname(file_name)) > 0:
#        if not os.path.exists(outdir + os.path.dirname(file_name)):
#            os.makedirs(outdir + os.path.dirname(file_name))
#    open(outdir + file_name, "wb").write(buf_u)
#    fd.close()
#
#def extract_archive(f, outdir="out/"):
#    i = 0
#    l_file = []
#    #z = zipfile.ZipFile('launcher.zip', 'r')
#    if not os.path.exists(outdir):
#        os.mkdir(outdir)
#    z = zipfile.ZipFile(f)
#    for info in z.infolist():
#        passw = extract_passw(info.extra, info.filename)
#        z.fp.seek(info.header_offset + 26)
#        file_name_len, extra_len = struct.unpack("<HH", z.fp.read(4))
#        file_name = z.fp.read(file_name_len)
#        #print file_name
#        z.fp.seek(info.header_offset + 30 + file_name_len + extra_len)
#        buf = z.fp.read(info.compress_size)
#        zd = _ZipDecrypter(passw)
#        buf = ''.join(zd(c) for c in buf)
#        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
#        buf_u = decoder.decompress(buf[0x0C:])
#        if len(os.path.dirname(info.filename)) > 0:
#            if not os.path.exists(outdir + os.path.dirname(info.filename)):
#                os.makedirs(outdir + os.path.dirname(info.filename))
#        open(outdir + info.filename, "wb").write(buf_u)
#        l_file.append(info.filename)
#    return l_file
#
#def rmpe(filename):
#    filesize = os.path.getsize(filename)
#    buf = open(filename, "rb").read()
#    e = PE(buf)
#    overlap_off = e.SHList[e.Coffhdr.numberofsections - 1].offset + e.SHList[e.Coffhdr.numberofsections - 1].size
#    if filesize > overlap_off:
#        if e.NThdr.optentries[4].rva != 0:  # 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
#            buf = buf[overlap_off:e.NThdr.optentries[4].rva]
#        else:
#            buf = buf[overlap_off:]
#        f = StringIO.StringIO(buf)
#        return f
#    return None
#
#def list_files(filename):
#    l_file = []
#    f = rmpe(filename)
#    z = zipfile.ZipFile(f)
#    for info in z.infolist():
#        l_file.append(info)
#    return l_file
#
#def extract_files(filename, outdir="out/"):
#    f = rmpe(filename)
#    return extract_archive(f, outdir)

if __name__ == '__main__':
    #tz = TESOZip("UPDATE_OUT/4/game_player_-1to4.zip", "UPDATE_OUT/4/")
    #for info in tz.zp.infolist():
    #    printinfo(info)
    #tz = TESOZip("UPDATE_OUT/72/game_player_-1to72.solidpkg")
    #tz.PrintInfos()
    #tz.ExtractFile("metafile.solid")

    tz = TESOZip("UPDATE_OUT/10/game_player_-1to10.zip", "UPDATE_OUT/10/", True)
    tz.PrintInfos()
    #tz.ExtractFile("client/eso.exe")

    #f = rmpe("UPDATE_OUT/4/game_player_-1to4.solidpkg")
    #zp = zipfile.ZipFile(f)
    #for info in zp.infolist():
    #    printinfo(info)
    #extract_files("UPDATE_OUT/-1to5/game_player_-1to5.solidpkg", "UPDATE_OUT/-1to5/")
    #l_info = list_files("UPDATE_OUT/3/game_player_2to3.zip")
    #l_info = list_files("UPDATE_OUT/25/game_player_-1to25.zip")
    #for info in l_info:
        #if info.filename == "client/eso.exe":
        #if info.filename == "client/game.mnf":
            #print hex(info.header_offset)
            #print hex(info.compress_size)
            #print hex(info.file_size)
            #print hex(info.compress_type)
            #print hex(info.flag_bits)
            #print dir(info)
            ##extract_comp_file("UPDATE_OUT/25/game_player_-1to25.z01", info.header_offset, info.compress_size, "UPDATE_OUT/25/")
            #extract_comp_file("UPDATE_OUT/3/game_player_2to3.z01", info.header_offset, info.compress_size, "UPDATE_OUT/3/")