import zipfile
from zipfile import _ZipDecrypter
import zlib
import struct
import sys
import os
from elfesteem.pe_init import PE
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

def compute_passw(passw):
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

def extract_passw(extra, filename):
    flag, length = struct.unpack("<HH", extra[0:4])
    if flag != 0x8810:
        print "[-] extract_passw - wrong flag!"
        sys.exit(42)
    if length > 0x78:
        length = 0x78
    passw = compute_passw(extra[4:4 + length])
    return passw

def extract_comp_file(filename, offset, length, outdir="out/"):
    fd = open(filename, "rb")
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
    print file_name
    flag, mm = struct.unpack("<HH", fd.read(4))
    #print "[+] flag: %04X" % flag
    fd.seek(offset + 30 + file_name_len + extra_len)
    buf = fd.read(length)
    #print hexdump(buf[:0x50])
    #print "-" * 10
    #print hexdump(buf[0x0D:0x20])
    decoder = zlib.decompressobj(-zlib.MAX_WBITS)
    buf_u = decoder.decompress(buf)
    #buf_u = zlib.decompress(buf[0xC:])
    if len(os.path.dirname(file_name)) > 0:
        if not os.path.exists(outdir + os.path.dirname(file_name)):
            os.makedirs(outdir + os.path.dirname(file_name))
    open(outdir + file_name, "wb").write(buf_u)
    fd.close()
    
def extract_archive(f, outdir="out/"):
    i = 0
    l_file = []
    #z = zipfile.ZipFile('launcher.zip', 'r')
    if not os.path.exists(outdir):
        os.mkdir(outdir)
    z = zipfile.ZipFile(f)
    for info in z.infolist():
        passw = extract_passw(info.extra, info.filename)
        z.fp.seek(info.header_offset + 26)
        file_name_len, extra_len = struct.unpack("<HH", z.fp.read(4))
        file_name = z.fp.read(file_name_len)
        #print file_name
        z.fp.seek(info.header_offset + 30 + file_name_len + extra_len)
        buf = z.fp.read(info.compress_size)
        zd = _ZipDecrypter(passw)
        buf = ''.join(zd(c) for c in buf)
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        buf_u = decoder.decompress(buf[0x0C:])
        if len(os.path.dirname(info.filename)) > 0:
            if not os.path.exists(outdir + os.path.dirname(info.filename)):
                os.makedirs(outdir + os.path.dirname(info.filename))
        open(outdir + info.filename, "wb").write(buf_u)
        l_file.append(info.filename)
    return l_file

def rmpe(filename):
    filesize = os.path.getsize(filename)
    buf = open(filename, "rb").read()
    e = PE(buf)
    overlap_off = e.SHList[e.Coffhdr.numberofsections - 1].offset + e.SHList[e.Coffhdr.numberofsections - 1].size
    if filesize > overlap_off:
        #print "overlap_off: %X" % overlap_off
        if e.NThdr.optentries[4].rva != 0:  # 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
            buf = buf[overlap_off:e.NThdr.optentries[4].rva]
        else:
            buf = buf[overlap_off:]
        #print hexdump(buf[:0x100])
        f = StringIO.StringIO(buf)
        return f
    return None
    
def list_files(filename):
    l_file = []
    f = rmpe(filename)
    z = zipfile.ZipFile(f)
    for info in z.infolist(): 
        l_file.append(info)
    return l_file
    
def extract_files(filename, outdir="out/"):
    f = rmpe(filename)
    return extract_archive(f, outdir)

if __name__ == '__main__':
    #extract_files("UPDATE_OUT/-1to5/game_player_-1to5.solidpkg", "UPDATE_OUT/-1to5/")
    l_info = list_files("UPDATE_OUT/3/game_player_2to3.zip")
    #l_info = list_files("UPDATE_OUT/25/game_player_-1to25.zip")
    for info in l_info:
        if info.filename == "client/eso.exe":
        #if info.filename == "client/game.mnf":
            print hex(info.header_offset)
            print hex(info.compress_size)
            print hex(info.file_size)
            print hex(info.compress_type)
            print hex(info.flag_bits)
            print dir(info)
            #extract_comp_file("UPDATE_OUT/25/game_player_-1to25.z01", info.header_offset, info.compress_size, "UPDATE_OUT/25/")
            extract_comp_file("UPDATE_OUT/3/game_player_2to3.z01", info.header_offset, info.compress_size, "UPDATE_OUT/3/")