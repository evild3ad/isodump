# isodump

isodump.py is a simple Python script utilized to assist incident responders analyzing ISO files (ISO 9660 disk image format) containing malware.

The following file systems are supported:

* [ISO 9660](https://en.wikipedia.org/wiki/ISO_9660)
* [Universal Disk Format](https://en.wikipedia.org/wiki/Universal_Disk_Format) (UDF)

```
file /opt/isodump/samples/Test.dmg
/opt/isodump/samples/Test.dmg: ISO 9660 CD-ROM filesystem data 'TEST'

file /opt/isodump/samples/PO#20190705.IMG
/opt/isodump/samples/PO#20190705.IMG: UDF filesystem data (version 1.5) 'PICTURES'
```
**Warning:** The directory `samples` contains real malware!

## Dependencies

Before you can use the script you will need to install the python library [isoparser](https://github.com/barneygale/isoparser) by Barney Gale.

```
sudo -H pip install six
sudo -H pip install isoparser
```

Tested on macOS 10.14.5

## Usage
```
python3 isodump.py -h

usage: isodump.py -i <file> [options]

ISO dump utility

optional arguments:
  -h, --help            show this help message and exit
  -d, --dump            dump file (default: item 0 to stdout)
  -i ISO, --iso ISO     iso file to analyze
  -l, --list            List all files from root directory (csv output)
  -M, --metadata        Print metadata
  -o [OUT], --out [OUT]
                        output folder (default: current working directory)
  -s [SELECT], --select [SELECT]
                        select item nr for dumping (a for all)
  --version             show program's version number and exit
```

## Quick Start

* List all files from root directory (csv output)
```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -l
Index;Name;Size;Header;MD5;SHA256
0;INVOICE_.EXE;1325568;4d5a9000030000000400;208cd564304ef7fe98a0c3da095fec3b;b3aef0e1d7a71edbc858a81e66f354be1974aafdd4449f2972e4dae1c82f2b8a
1;PAYMENT SLIP AND BANK CONF.EXE;709632;4d5a5000020000000400;eccd7c33037181277ae23f3c3b5baf74;84b73d9bc64da09072ebba537418a35c4883daba40fa7b348080fa10b1dfeb41
2;PO_20190.EXE;610816;4d5a9000030000000400;663ece11cb6b12d23266884d7b89e47a;2d8f0de8c52452cc12e8d4f993f0aad60457c3cd396632546da0f501b066ff3f

python3 isodump.py -i /opt/isodump/samples/Test.dmg -l | column -s ";" -t
Index  Name                            Size     Header                MD5                               SHA256
0      INVOICE_.EXE                    1325568  4d5a9000030000000400  208cd564304ef7fe98a0c3da095fec3b  b3aef0e1d7a71edbc858a81e66f354be1974aafdd4449f2972e4dae1c82f2b8a
1      PAYMENT SLIP AND BANK CONF.EXE  709632   4d5a5000020000000400  eccd7c33037181277ae23f3c3b5baf74  84b73d9bc64da09072ebba537418a35c4883daba40fa7b348080fa10b1dfeb41
2      PO_20190.EXE                    610816   4d5a9000030000000400  663ece11cb6b12d23266884d7b89e47a  2d8f0de8c52452cc12e8d4f993f0aad60457c3cd396632546da0f501b066ff3f
```

* Print metadata of iso file

```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -M

volume name = TEST
volume block count = 1839
volume block size = 2048
voulme size = 3766272
volume set name = 
volume software = 
volume create root dir = 2019-05-13 16:10:36
volume create volume = 2019051314120000
volume modify = 2019051314120000
```

* Extract all files from root directory
```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s a -o /Users/evild3ad/Desktop/dump/
```

* Extract specific file from root directory

```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d -s 1 -o /Users/evild3ad/Desktop/dump/

```
* Pipe file into other tools (default: item 0 to stdout)

```
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d | python tools/file-magic/file-magic.py
python3 isodump.py -i /opt/isodump/samples/Test.dmg -d | python tools/pecheck/pecheck.py | less
```

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

## License
isodump - ISO dump utility Copyright (c) 2019 Martin Willing

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see [http://www.gnu.org/licenses/licenses.en.html](http://www.gnu.org/licenses/licenses.en.html)
