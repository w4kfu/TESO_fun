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

def extract_archive(f, outdir="out/"):
    i = 0
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
        stfu, extra_len = struct.unpack("<HH", z.fp.read(4))
        z.fp.seek(info.header_offset + 30 + file_name_len + 4 + extra_len)
        buf = z.fp.read(info.compress_size)
        zd = _ZipDecrypter(passw)
        buf = ''.join(zd(c) for c in buf)
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        buf_u = decoder.decompress(buf[0x0C:])
        if len(os.path.dirname(info.filename)) > 0:
            if not os.path.exists(outdir + os.path.dirname(info.filename)):
                os.makedirs(outdir + os.path.dirname(info.filename))
        open(outdir + info.filename, "wb").write(buf_u)

def extract_files(filename, outdir="out/"):
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
        print hexdump(buf[:0x100])
        f = StringIO.StringIO(buf)
        extract_archive(f, outdir)

#extract_files("Bethesda.net_Launcher.exe")
#extract_files("Bethesda.net_Launcher.patchmanifest")
#extract_files("Bethesda.net_Launcher_-1to0.solidpkg")
#extract_files("depot.patchmanifest")
#extract_files("game_player.patchmanifest")
#extract_files("depot_67to68.solidpkg")
#extract_files("game_player_-1to95.solidpkg")
#extract_files("game_player_-1to95.zip")
#extract_files("TEST.zip")
#extract_archive("game_player_-1to95.zip")
