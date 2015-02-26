import urllib
import os
import sys
import xml.etree.ElementTree as ET

import TESOZip

OUTDIR = 'UPDATE_OUT/'

HOST_LAUNCHER = 'launcher.bethesda.net'
HOST_LIVEPATCHER = 'live.patcher.elderscrollsonline.com'

class Release:
    def __init__(self, idd, sha1, name):
        self.id = idd
        self.sha1 = sha1
        self.name = name
        self.patchdatetime = ""
        self.metafileurl = ""

    def __str__(self):
        b = "[+] id            : %s\n" % self.id
        b += "[+] sha1          : %s\n" % self.sha1
        b += "[+] name          : %s\n" % self.name
        b += "[+] patchdatetime : %s\n" % self.patchdatetime
        b += "[+] metafileurl   : %s\n" % self.metafileurl
        return b

if not os.path.exists(OUTDIR):
    os.mkdir(OUTDIR)
#urllib.urlretrieve ("http://launcher.bethesda.net/ESO/game_player.patchmanifest", OUTDIR + "game_player.patchmanifest")
l_file = TESOZip.extract_files(OUTDIR + "game_player.patchmanifest", OUTDIR)
if "manifest.xml" not in l_file:
    print "[-] no xml extracted :("
    print l_file
    sys.exit(1)
tree = ET.parse(OUTDIR + "manifest.xml")
root = tree.getroot()
releases = {}

for release in root.iter('Release'):
    rlz_id = release.find('Id').text
    rlz_sha1 = release.find('SHA1').text
    rlz_name = release.find('Name').text
    releases[rlz_id] = Release(rlz_id, rlz_sha1, rlz_name)
    
#print releases
print len(releases)

for i in xrange(0, len(releases)):
    for release in root.iter('ReleaseUpdatePath'):
        rlz_from = release.find('From').text
        rlz_to = release.find('To').text
        if int(rlz_from) == (i - 1) and int(rlz_to) == i:
            for extradataitem in release.iter('ExtraDataItem'): 
                if extradataitem.find('Key').text == 'ZoPatchDateTime':
                    releases[str(i)].patchdatetime = extradataitem.find('Value').text
                if extradataitem.find('Key').text == 'MetafileUrl':
                    releases[str(i)].metafileurl = extradataitem.find('Value').text

for k in releases:
    print releases[k]
    print "-" * 20
                    
sys.exit(42)
