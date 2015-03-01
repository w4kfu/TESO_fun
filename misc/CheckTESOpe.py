import os
import re
import fnmatch
import struct
import elfesteem.pe_init
from capstone import *
from capstone.x86 import *

# "Jessie J - Nobodys Perfect (Netsky Remix)"

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines).rstrip('\n')

def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename

def CheckAES(buf):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    pos_1 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\x68....\x68", buf)]
    #print pos_1
    pos_2 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\xE9", buf)]
    pos_3 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\x68....\xE9", buf)]
    #print pos_1
    if len(pos_1) == 0 and len(pos_2) == 0 and len(pos_3) == 0:
        print "FU:("
        sys.exit(42)
    if len(pos_1) > 1 or len(pos_2) > 1 or len(pos_2) > 1:
        for pos in pos_1:
            for i in md.disasm(buf[pos:pos + 0x10], 0x1000):
                print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
            print "-" * 10
        for pos in pos_2:
            for i in md.disasm(buf[pos:pos + 0x10], 0x1000):
                print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
            print "-" * 10
        print pos_1
        print pos_2
        print "AGAIN FU"
        sys.exit(42)
    if len(pos_1) >= 1 and len(pos_2) >= 1 and len(pos_2) >= 1:
        print "RE FU"
        sys.exit(42)
    if len(pos_3) == 1:
        pos_1 = pos_3
    if len(pos_1) == 1:
        pe = elfesteem.pe_init.PE(buf)
        dis = list(md.disasm(buf[pos_1[0] + 5:pos_1[0] + 5 + 5], pe.off2virt(pos_1[0] + 5)))
        va_key = dis[0].operands[0].value.imm
        off_key = pe.virt2off(va_key)
        aes_key = buf[off_key:off_key + 0x80]
        print "[+] AES KEY:"
        print hexdump(aes_key)
    if len(pos_2) == 1:
        pe = elfesteem.pe_init.PE(buf)
        dst_jmp = (struct.unpack("<I", buf[pos_2[0] + 5 + 1:pos_2[0] + 5 + 1 + 4])[0] + pe.off2virt(pos_2[0]) + 5 + 5) & 0xFFFFFFFF
        #print "[+] val_jmp : 0x%08X" % struct.unpack("<I", buf[pos_2[0] + 5 + 1:pos_2[0] + 5 + 1 + 4])[0]
        #dst_jmp = (struct.unpack("<I", buf[pos_2[0] + 5 + 1:pos_2[0] + 5 + 1 + 4])[0] + pos_2[0] + 5 + 5) & 0xFFFFFFFF
        off_jmp = pe.virt2off(dst_jmp)
        #print "[+] dst_jmp : 0x%08X" % dst_jmp
        #print pe.off2virt(dst_jmp + 5)
        dis = list(md.disasm(buf[off_jmp:off_jmp + 5], dst_jmp))
        va_key = dis[0].operands[0].value.imm
        off_key = pe.virt2off(va_key)
        aes_key = buf[off_key:off_key + 0x80]
        print "[+] AES KEY:"
        print hexdump(aes_key)
        #print "[+] dst_jmp : 0x%08X" % dst_jmp
        #print "POS2!"
        #sys.exit(42)
    l_pos = [m.start() for m in re.finditer("\x00\x10\x00\x00\x02\x00\x00\x00\x00\x20\x00\x00", buf)]
    if len(l_pos) == 0:
        print "fu la struct"
        sys.exit(42)
    if len(l_pos) > 1:
        print "re fu re fu la struct"
        sys.exit(42)
    
def TestCheckAES():
    l = ['EXE_OUT\\2013_12_14-live.703011-eso.exe', 'EXE_OUT\\2013_12_21-live.707462-eso.exe', 'EXE_OUT\\2013_12_31-live.708405-eso.exe', 'EXE_OUT\\2014_01_03-live.709492-eso.exe', 'EXE_OUT\\2014_01_06-live.709717-eso.exe', 'EXE_OUT\\2014_01_10-live.714440-eso.exe', 'EXE_OUT\\2014_01_23-live.722888-eso.exe', 'EXE_OUT\\2014_01_30-live.727776-eso.exe', 'EXE_OUT\\2014_02_03-live.729240-eso.exe', 'EXE_OUT\\2014_02_04-live.730552-eso.exe', 'EXE_OUT\\2014_02_24-live.779987-eso.exe', 'EXE_OUT\\2014_03_03-live.813002-eso.exe', 'EXE_OUT\\2014_03_05-live.853795-eso.exe','EXE_OUT\\2014_03_06-live.872628-eso.exe', 'EXE_OUT\\2014_03_07-live.892895-eso.exe', 'EXE_OUT\\2014_03_11-live.913319-eso.exe', 'EXE_OUT\\2014_03_13-live.932702-eso.exe', 'EXE_OUT\\2014_03_18-live.950966-eso.exe', 'EXE_OUT\\2014_03_20-live.953228-eso.exe', 'EXE_OUT\\2014_03_25-live.956218-eso.exe', 'EXE_OUT\\2014_03_25-live.956797-eso.exe', 'EXE_OUT\\2014_03_31-live.961670-eso.exe', 'EXE_OUT\\2014_04_01-live.962094-eso.exe', 'EXE_OUT\\2014_04_02-live.962845-eso.exe', 'EXE_OUT\\2014_04_05-live.964407-eso.exe', 'EXE_OUT\\2014_04_05-live.964486-eso.exe', 'EXE_OUT\\2014_04_13-live.968198-eso.exe', 'EXE_OUT\\2014_04_15-live.969974-eso.exe', 'EXE_OUT\\2014_04_17-live.971785-eso.exe', 'EXE_OUT\\2014_04_19-live.972476-eso.exe', 'EXE_OUT\\2014_04_25-live.976505-eso.exe', 'EXE_OUT\\2014_05_02-live.980599-eso.exe', 'EXE_OUT\\2014_05_09-live.984658-eso.exe', 'EXE_OUT\\2014_05_19-live.990526-eso.exe', 'EXE_OUT\\2014_05_24-live.995677-eso.exe', 'EXE_OUT\\2014_05_27-live.996465-eso.exe', 'EXE_OUT\\2014_05_30-live.998959-eso.exe', 'EXE_OUT\\2014_06_05-live.1002775-eso.exe', 'EXE_OUT\\2014_06_12-live.1006103-eso.exe','EXE_OUT\\2014_06_22-live.1010890-eso.exe', 'EXE_OUT\\2014_06_26-live.1013841-eso.exe', 'EXE_OUT\\2014_07_01-live.1015265-eso.exe', 'EXE_OUT\\2014_07_03-live.1016351-eso.exe', 'EXE_OUT\\2014_07_07-live.1017350-eso.exe', 'EXE_OUT\\2014_07_18-live.1023797-eso.exe', 'EXE_OUT\\2014_07_31-live.1030847-eso.exe', 'EXE_OUT\\2014_08_07-live.1034504-eso.exe', 'EXE_OUT\\2014_08_12-live.1036379-eso.exe', 'EXE_OUT\\2014_08_21-live.1041552-eso.exe', 'EXE_OUT\\2014_09_13-live.1052207-eso.exe', 'EXE_OUT\\2014_09_16-live.1053773-eso.exe', 'EXE_OUT\\2014_09_18-live.1055280-eso.exe', 'EXE_OUT\\2014_09_27-live.1059112-eso.exe', 'EXE_OUT\\2014_10_06-live.1062940-eso.exe', 'EXE_OUT\\2014_10_07-live.1063187-eso.exe', 'EXE_OUT\\2014_10_09-live.1065307-eso.exe', 'EXE_OUT\\2014_10_14-live.1067458-eso.exe', 'EXE_OUT\\2014_10_31-live.1076350-eso.exe', 'EXE_OUT\\2014_11_07-live.1080596-eso.exe', 'EXE_OUT\\2014_11_11-live.1081567-eso.exe', 'EXE_OUT\\2014_11_13-live.1083564-eso.exe', 'EXE_OUT\\2014_11_21-live.1087242-eso.exe', 'EXE_OUT\\2014_11_25-live.1088592-eso.exe', 'EXE_OUT\\2014_12_04-live.1091904-eso.exe', 'EXE_OUT\\2015_01_08-live.1103478-eso.exe']
    #l = ['EXE_OUT\\2014_01_23-live.722888-eso.exe']
    for tesope in l:
        print "[+] Working on %s" % tesope
        buf = open(tesope, "rb").read()
        CheckAES(buf)
    print "[+] done"
        
if __name__ == '__main__':
    TestCheckAES()
    sys.exit(42)
    l_packed = []
    l_notpacked = []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    for tesope in find_files("EXE_OUT", "*.exe"):
        print "[+] Working on %s" % tesope
        buf = open(tesope, "rb").read()
        pe = elfesteem.pe_init.PE(buf)
        print "[+] nb sections : %d" % pe.Coffhdr.numberofsections
        print [sec.name for sec in pe.SHList]
        buf = pe.drva[pe.Opthdr.AddressOfEntryPoint:pe.Opthdr.AddressOfEntryPoint + 10]
        for i in md.disasm(buf, pe.NThdr.ImageBase + pe.Opthdr.AddressOfEntryPoint):
            print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
        if buf[0] == "\xE9":
            print "Packed?"
            l_packed.append(tesope)
        elif buf[0] == "\xE8":
            print "Not packed?"
            l_notpacked.append(tesope)
        else:
            print "unknow!"
            sys.exit(42)
        print "-" * 20
    print "[+] packed:"
    print l_packed
    print "[+] not packed:"
    print l_notpacked