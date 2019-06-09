# isodump

isodump.py is a simple Python script utilized to assist incident responders analyzing ISO files (ISO 9660 disk image format) containing malware.

The following file systems are supported:

* [ISO 9660](https://en.wikipedia.org/wiki/ISO_9660)
* [Universal Disk Format](https://en.wikipedia.org/wiki/Universal_Disk_Format) (UDF)

file /opt/isodump/samples/Test.dmg<br />
/opt/isodump/samples/Test.dmg: ISO 9660 CD-ROM filesystem data 'TEST'<br />

file /opt/isodump/samples/PO#20190705.IMG<br />
/opt/isodump/samples/PO#20190705.IMG: UDF filesystem data (version 1.5) 'PICTURES'<br />

## Dependencies

Before you can use the script you will need to install the python library [isoparser] by Barney Gale (https://github.com/barneygale/isoparser).

sudo -H pip install six<br />
sudo -H pip install isoparser<br />

Tested on macOS 10.14.5

## Usage

python3 isodump.py -h

usage: isodump.py -i <file> [options]

ISO dump utility

optional arguments:
  -h, --help            show this help message and exit<br />
  -d, --dump            dump file (default: item 0 to stdout)<br />
  -i ISO, --iso ISO     iso file to analyze<br />
  -l, --list            List all files from root directory (csv output)<br />
  -M, --metadata        Print metadata<br />
  -o [OUT], --out [OUT]<br />
                        output folder (default: current working directory)<br />
  -s [SELECT], --select [SELECT]<br />
                        select item nr for dumping (a for all)<br />
  --version             show program's version number and exit<br />

## Quick Start

* List all files from root directory (csv output)

python3 isodump.py -i /opt/isodump/samples/Test.dmg -l<br />
Index;Name;Size;Header;MD5;SHA256
0;INVOICE_.EXE;1325568;4d5a9000030000000400;208cd564304ef7fe98a0c3da095fec3b;b3aef0e1d7a71edbc858a81e66f354be1974aafdd4449f2972e4dae1c82f2b8a
1;PAYMENT SLIP AND BANK CONF.EXE;709632;4d5a5000020000000400;eccd7c33037181277ae23f3c3b5baf74;84b73d9bc64da09072ebba537418a35c4883daba40fa7b348080fa10b1dfeb41
2;PO_20190.EXE;610816;4d5a9000030000000400;663ece11cb6b12d23266884d7b89e47a;2d8f0de8c52452cc12e8d4f993f0aad60457c3cd396632546da0f501b066ff3f

python3 isodump.py -i /opt/isodump/samples/Test.dmg -l | column -s ";" -t<br />
Index  Name                            Size     Header                MD5                               SHA256
0      INVOICE_.EXE                    1325568  4d5a9000030000000400  208cd564304ef7fe98a0c3da095fec3b  b3aef0e1d7a71edbc858a81e66f354be1974aafdd4449f2972e4dae1c82f2b8a
1      PAYMENT SLIP AND BANK CONF.EXE  709632   4d5a5000020000000400  eccd7c33037181277ae23f3c3b5baf74  84b73d9bc64da09072ebba537418a35c4883daba40fa7b348080fa10b1dfeb41
2      PO_20190.EXE                    610816   4d5a9000030000000400  663ece11cb6b12d23266884d7b89e47a  2d8f0de8c52452cc12e8d4f993f0aad60457c3cd396632546da0f501b066ff3f

* Print metadata of iso file

python3 isodump.py -i /opt/isodump/samples/Test.dmg -M<br />

volume name = TEST<br />
volume block count = 1839<br />
volume block size = 2048<br />
voulme size = 3766272<br />
volume set name = <br />
volume software = <br />
volume create root dir = 2019-05-13 16:10:36<br />
volume create volume = 2019051314120000<br />
volume modify = 2019051314120000<br />

* Extract all files from root directory

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s a -o /Users/evild3ad/Desktop/dump/

* Extract specific file from root directory

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 1 -o /Users/evild3ad/Desktop/dump/ <br />

* Pipe file into other tools (default: item 0 to stdout)

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d | python tools/file-magic/file-magic.py <br />
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d | python tools/pecheck/pecheck.py | less <br />

* Pipe specific file into other tools

```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 2 | python tools/file-magic/file-magic.py
PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 2 | python tools/pecheck/pecheck.py | less

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 1 | xxd | head
00000000: 4d5a 5000 0200 0000 0400 0f00 ffff 0000  MZP.............
00000010: b800 0000 0000 0000 4000 1a00 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0001 0000  ................
00000040: ba10 000e 1fb4 09cd 21b8 014c cd21 9090  ........!..L.!..
00000050: 5468 6973 2070 726f 6772 616d 206d 7573  This program mus
00000060: 7420 6265 2072 756e 2075 6e64 6572 2057  t be run under W
00000070: 696e 3332 0d0a 2437 0000 0000 0000 0000  in32..$7........
00000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000090: 0000 0000 0000 0000 0000 0000 0000 0000  ................

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 2 | xxd | head
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 1001 0000  ................
00000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.!Th
00000050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
00000060: 7420 6265 2072 756e 2069 6e20 444f 5320  t be run in DOS 
00000070: 6d6f 6465 2e0d 0d0a 2400 0000 0000 0000  mode....$.......
00000080: 1673 9292 5212 fcc1 5212 fcc1 5212 fcc1  .s..R...R...R...
00000090: 1443 1dc1 5012 fcc1 ccb2 3bc1 5312 fcc1  .C..P.....;.S...

python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 2 | file -
/dev/stdin: PE32 executable (GUI) Intel 80386, for MS Windows, UPX compressed
```
