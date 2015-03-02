import os
import re
import fnmatch
import struct
import elfesteem.pe_init
from capstone import *
from capstone.x86 import *
from Crypto.Cipher import AES
import shutil

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

def GetAES_KEY(buf, pe):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    # PUSH 0x80 ; PUSH OFFSET AES_KEY ; PUSH OFFSET AES_CONTEXT
    pos_1 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\x68....\x68", buf)]
    # PUSH 0x80 ; JMP LOC_00 ; LOC_00 : PUSH OFFSET AES_KEY
    pos_2 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\xE9", buf)]
    # PUSH 0x80 ; PUSH OFFSET AES_KEY ; JMP LOC_00 ; LOC_00 : PUSH OFFSET AES_CONTEXT
    pos_3 = [m.start() for m in re.finditer("\x68\x80\x00\x00\x00\x68....\xE9", buf)]
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
        dis = list(md.disasm(buf[pos_1[0] + 5:pos_1[0] + 5 + 5], pe.off2virt(pos_1[0] + 5)))
        va_key = dis[0].operands[0].value.imm
        off_key = pe.virt2off(va_key)
        AES_KEY = buf[off_key:off_key + 16]
        print "[+] AES KEY:"
        print hexdump(AES_KEY)
    if len(pos_2) == 1:
        dst_jmp = (struct.unpack("<I", buf[pos_2[0] + 5 + 1:pos_2[0] + 5 + 1 + 4])[0] + pe.off2virt(pos_2[0]) + 5 + 5) & 0xFFFFFFFF
        off_jmp = pe.virt2off(dst_jmp)
        dis = list(md.disasm(buf[off_jmp:off_jmp + 5], dst_jmp))
        va_key = dis[0].operands[0].value.imm
        off_key = pe.virt2off(va_key)
        AES_KEY = buf[off_key:off_key + 16]
        print "[+] AES KEY:"
        print hexdump(AES_KEY)
    return AES_KEY
    
def SearchStartTable(buf, pos, pe):
    block = []
    section = {}
    start_pos = pos
    print "pos:  ", hex(pos)
    val = struct.unpack("<I", buf[pos - 8: pos - 4])[0]
    pos = pos - 8
    while struct.unpack("<I", buf[pos - 8: pos - 4])[0] < val: # AND PE VA ETC
        v = struct.unpack("<I", buf[pos: pos + 4])[0]
        s = struct.unpack("<I", buf[pos + 4: pos + 8])[0]
        block.append((v, s))
        val = struct.unpack("<I", buf[pos - 8: pos - 4])[0]
        pos = pos - 8
    v = struct.unpack("<I", buf[pos: pos + 4])[0]
    s = struct.unpack("<I", buf[pos + 4: pos + 8])[0]
    block.append((v, s))   
    block.reverse()
    print "[+] Start at %08X ?" % pos
    print "[+] Nb       %08X ?" % ((start_pos - pos) / 8)
    for sec in pe.SHList:
        section[sec.name] = 0
    for v, s in block:
        for sec in pe.SHList:
            if v <= (sec.addr + sec.size):
                section[sec.name] += 1
    print section
    return block
    
def GetBlockOffset(buf, pe):
    #print hexdump(buf[0x1A73980:0x1A73990])
    for i in xrange(0, len(buf) - 0x10):
        if buf[i] == "\x00" and buf[i + 1] == "\xFF" and buf[i + 2] == "\xFF" and buf[i + 3] == "\xFF" and buf[i + 4] == "\xFF": 
            if buf[i + 5] != "\xFF" or buf[i + 6] != "\xFF" or buf[i + 7] != "\xFF" or buf[i + 8] != "\xFF":
                if buf[i + 9] == "\xFF" and buf[i + 10] == "\xFF" and buf[i + 11] == "\xFF" and buf[i + 12] == "\xFF" and buf[i + 13] == "\xFF":
                    #print "FOUND!"
                    pos = i + 1
    #for m in re.finditer('\xff\xff\xff\xff....\xff\xff\xff\xff\xff\xff\xff\xff', buf):
        #pos = m.start()
        #if pos > 0x1A73900 and pos < 0x1A73990:
        #    print "m.start() : " + hex(pos)
                    val_1 = struct.unpack("<I", buf[pos - 8: pos - 4])[0]
                    #print hex(val_1)
                    val_2 = struct.unpack("<I", buf[pos - 16: pos - 12])[0]
                    val_3 = struct.unpack("<I", buf[pos - 24: pos - 20])[0]
                    val_4 = struct.unpack("<I", buf[pos - 32: pos - 28])[0]
                    if val_2 < val_1 and val_3 < val_2 and val_4 < val_3:
                        return SearchStartTable(buf, pos, pe)
    return []
            
def ApplyAES(AESKey, block, buf, pe):
    print hexdump(AESKey)
    obj = AES.new(AESKey, AES.MODE_ECB)
    b = ""
    print hex(block[0][0])
    print hex(block[-1][0])
    for v, s in block:
        off = pe.rva2off(v)
        b += buf[off: off + s]
    if len(b) % 16 != 0:
        b += '\x00' * (16 - len(b) % 16)
    bd = obj.decrypt(b)
    print hexdump(bd[:0x10])
    #open("lol.bin", "wb").write(bd)
    return bd
    
def TestCheckAES():
    #l = ['EXE_OUT\\2013_12_14-live.703011-eso.exe', 'EXE_OUT\\2013_12_21-live.707462-eso.exe', 'EXE_OUT\\2013_12_31-live.708405-eso.exe', 'EXE_OUT\\2014_01_03-live.709492-eso.exe', 'EXE_OUT\\2014_01_06-live.709717-eso.exe', 'EXE_OUT\\2014_01_10-live.714440-eso.exe', 'EXE_OUT\\2014_01_23-live.722888-eso.exe', 'EXE_OUT\\2014_01_30-live.727776-eso.exe', 'EXE_OUT\\2014_02_03-live.729240-eso.exe', 'EXE_OUT\\2014_02_04-live.730552-eso.exe', 'EXE_OUT\\2014_02_24-live.779987-eso.exe', 'EXE_OUT\\2014_03_03-live.813002-eso.exe', 'EXE_OUT\\2014_03_05-live.853795-eso.exe','EXE_OUT\\2014_03_06-live.872628-eso.exe', 'EXE_OUT\\2014_03_07-live.892895-eso.exe', 'EXE_OUT\\2014_03_11-live.913319-eso.exe', 'EXE_OUT\\2014_03_13-live.932702-eso.exe', 'EXE_OUT\\2014_03_18-live.950966-eso.exe', 'EXE_OUT\\2014_03_20-live.953228-eso.exe', 'EXE_OUT\\2014_03_25-live.956218-eso.exe', 'EXE_OUT\\2014_03_25-live.956797-eso.exe', 'EXE_OUT\\2014_03_31-live.961670-eso.exe', 'EXE_OUT\\2014_04_01-live.962094-eso.exe', 'EXE_OUT\\2014_04_02-live.962845-eso.exe', 'EXE_OUT\\2014_04_05-live.964407-eso.exe', 'EXE_OUT\\2014_04_05-live.964486-eso.exe', 'EXE_OUT\\2014_04_13-live.968198-eso.exe', 'EXE_OUT\\2014_04_15-live.969974-eso.exe', 'EXE_OUT\\2014_04_17-live.971785-eso.exe', 'EXE_OUT\\2014_04_19-live.972476-eso.exe', 'EXE_OUT\\2014_04_25-live.976505-eso.exe', 'EXE_OUT\\2014_05_02-live.980599-eso.exe', 'EXE_OUT\\2014_05_09-live.984658-eso.exe', 'EXE_OUT\\2014_05_19-live.990526-eso.exe', 'EXE_OUT\\2014_05_24-live.995677-eso.exe', 'EXE_OUT\\2014_05_27-live.996465-eso.exe', 'EXE_OUT\\2014_05_30-live.998959-eso.exe', 'EXE_OUT\\2014_06_05-live.1002775-eso.exe', 'EXE_OUT\\2014_06_12-live.1006103-eso.exe','EXE_OUT\\2014_06_22-live.1010890-eso.exe', 'EXE_OUT\\2014_06_26-live.1013841-eso.exe', 'EXE_OUT\\2014_07_01-live.1015265-eso.exe', 'EXE_OUT\\2014_07_03-live.1016351-eso.exe', 'EXE_OUT\\2014_07_07-live.1017350-eso.exe', 'EXE_OUT\\2014_07_18-live.1023797-eso.exe', 'EXE_OUT\\2014_07_31-live.1030847-eso.exe', 'EXE_OUT\\2014_08_07-live.1034504-eso.exe', 'EXE_OUT\\2014_08_12-live.1036379-eso.exe', 'EXE_OUT\\2014_08_21-live.1041552-eso.exe', 'EXE_OUT\\2014_09_13-live.1052207-eso.exe', 'EXE_OUT\\2014_09_16-live.1053773-eso.exe', 'EXE_OUT\\2014_09_18-live.1055280-eso.exe', 'EXE_OUT\\2014_09_27-live.1059112-eso.exe', 'EXE_OUT\\2014_10_06-live.1062940-eso.exe', 'EXE_OUT\\2014_10_07-live.1063187-eso.exe', 'EXE_OUT\\2014_10_09-live.1065307-eso.exe', 'EXE_OUT\\2014_10_14-live.1067458-eso.exe', 'EXE_OUT\\2014_10_31-live.1076350-eso.exe', 'EXE_OUT\\2014_11_07-live.1080596-eso.exe', 'EXE_OUT\\2014_11_11-live.1081567-eso.exe', 'EXE_OUT\\2014_11_13-live.1083564-eso.exe', 'EXE_OUT\\2014_11_21-live.1087242-eso.exe', 'EXE_OUT\\2014_11_25-live.1088592-eso.exe', 'EXE_OUT\\2014_12_04-live.1091904-eso.exe', 'EXE_OUT\\2015_01_08-live.1103478-eso.exe']
    l = ['EXE_OUT\\2014_01_23-live.722888-eso.exe']
    #l = ['EXE_OUT\\2013_12_14-live.703011-eso.exe']
    for tesope in l:
        print "[+] Working on %s" % tesope
        buf = open(tesope, "rb").read()
        pe = elfesteem.pe_init.PE(buf)
        AES_KEY = GetAES_KEY(buf, pe)
        block = GetBlockOffset(buf, pe)
        ApplyAES(AES_KEY, block, buf, pe)
    print "[+] done"
        
def Decryptbin(filename="EXE_OUT\\2014_06_12-live.1006103-eso.exe"):
    buf = open(filename, "rb").read()
    pe = elfesteem.pe_init.PE(buf)
    AES_KEY = GetAES_KEY(buf, pe)
    block = GetBlockOffset(buf, pe)
    bd = ApplyAES(AES_KEY, block, buf, pe)
    shutil.copyfile(filename, "out/" + os.path.basename(filename) + "_un.exe")
    fd = open("out/" + os.path.basename(filename) + "_un.exe", "rb+")
    pos = 0
    for v, s in block:
        off = pe.rva2off(v)
        fd.seek(off, 0)
        fd.write(bd[pos: pos + s])
        pos += s
    fd.close()
        
if __name__ == '__main__':
    #TestCheckAES()
    #Decryptbin()
    Decryptbin("EXE_OUT\\2014_06_22-live.1010890-eso.exe")
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