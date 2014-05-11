from idaapi import *
from idc import *
from idautils import *

# Found in crc16.cpp from flair
def CRC16(data):
    POLY = 0xA001
    crc = 0xFFFF
    for c in data:
        c = ord(c)
        for i in xrange(0, 8):
            if (crc ^ c) & 1:
                crc = (crc >> 1) ^ POLY
            else:
                crc >>= 1
            c >>= 1
    c = (~c) & 0xFFFF
    data = crc
    crc = (crc << 8) | ((data >> 8) & 0xFF)
    return crc

def MakePatFunc(func):
    func_start_ea = func.startEA
    func_end_ea = func.endEA
    func_len = func_end_ea - func_start_ea
    #print "[+] Start : %08X" % func_start_ea
    #print "[+] End : %08X" % func_end_ea
    ea = func_start_ea
    while ea - func_start_ea < func_len:
        l_ref = [i for i in DataRefsFrom(ea)]
        if len(l_ref) > 0:
            # Data location referenced
            ref_ea = l_ref[0]
            print "[-] TODO"
            return
        else:
            l_ref = [i for i in CodeRefsFrom(ea, 0)]
            if len(l_ref) > 0:
                # Code location referenced
                ref_ea = l_ref[0]
                if (ref_ea < func_start_ea) or (ref_ea >= func_start_ea + func_len):
                    print hex(ref_ea)
                    print "[-] TODO"
                    return
        ea = NextHead(ea)
    first_str_len = 32 if func_len > 32 else func_len
    first_str = GetManyBytes(func_start_ea, first_str_len).encode('hex')
    for i in xrange(0, 32 - first_str_len):
        first_str += ".."
    #print first_str
    pos = 32
    crc = ""
    while pos < func_len and pos < (255 + 32):
        crc += chr(Byte(func_start_ea + pos))
        pos += 1
    alen = pos - 32
    crc = CRC16(crc)
    #print "[+] CRC = %04X" % crc
    pat_res = "%s %02X %04X %04X " % (first_str, alen, crc, func_len)
    pat_res += ":0000 %s" % get_func_name(func_start_ea)
    print pat_res
    #print "[+] Finish"

ea = get_screen_ea()
func = get_func(ea)
#if func == None:
    #print "[-] Not in a function"
#else:
#print func
MakePatFunc(func)
