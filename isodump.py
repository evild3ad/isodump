#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# isodump.py v0.1
#
# @author:      Martin Willing
# @copyright:   No copyright. Use at your own risk.
# @contact:     Any feedback or suggestions are always welcome and much appreciated - mwilling@evild3ad.com
# @url:         https://evild3ad.com
# @date:        2019-06-09
#
#              _ _     _ _____           _
#    _____   _(_) | __| |___ /  __ _  __| |
#   / _ \ \ / / | |/ _` | |_ \ / _` |/ _` |
#  |  __/\ V /| | | (_| |___) | (_| | (_| |
#   \___| \_/ |_|_|\__,_|____/ \__,_|\__,_|
#
#
# README
# isodump.py is a simple Python script utilized to assist incident responders analyzing ISO files (ISO 9660 disk image format) containing malware.
#
#
# usage: isodump.py -i <file> [options]
#
# ISO dump utility
#
# optional arguments:
#   -h, --help            show this help message and exit
#   -d, --dump            dump file (default: item 0 to stdout)
#   -i ISO, --iso ISO     iso file to analyze
#   -l, --list            List all files from root directory (csv output)
#   -M, --metadata        Print metadata
#   -o [OUT], --out [OUT]
#                         output folder (default: current working directory)
#   -s [SELECT], --select [SELECT]
#                         select item nr for dumping (a for all)
#   --version             show program's version number and exit
#
#
# Dependencies:
#
# Python 3.7.3 (2019-03-25)
# https://www.python.org/downloads/
#
# pip 19.1.2 (2019-05-06)
# https://pypi.org/project/pip/
#
# isoparser v0.3 (2017-02-03)
# https://github.com/barneygale/isoparser
# sudo -H pip install six
# sudo -H pip install isoparser
#
#
# Changelog:
# Version 0.1
# Release date: 2019-06-09
# Added: Listing directory contents
# Added: Extracting files
# Added: Hashing files
# Added: Piping files to stdout
# Added: Printing volume metadata
#
#
# Version 0.2
# Release date: 2019-xx-xx
# Added: Printing manual --> TODO
# Fixed: Other minor fixes and improvements --> TODO
#
#
# Tested on macOS 10.14.5
#
#############################################################
#############################################################

import argparse
import hashlib
import isoparser
import os
import platform
import sys

def checkFile(isoFile):
    # function for a simple file check
    if not os.access(isoFile, os.R_OK):
        print("[Error] input file does not exist or is not readable.")
        sys.exit()

def isoAnalyzer(isoFile):
    # function uses the isoparser script as a foundation for all other main functions
    try:
        parsedIso = isoparser.parse(isoFile)
        return parsedIso
    except:
        print("[Error] isoparser was not able to parse the input file.")
        sys.exit()

def isoExtract(parsedIso, outFolder, itemSelect):
    # function to dump file content to folder
    if itemSelect == 'A' or itemSelect == 'a':
        for file in parsedIso.root.children:
            fileName = file.name.decode('utf-8')
            fileContent = file.content
            saveFile(fileName, fileContent, outFolder)
    else:
        try:
            itemSelectint = int(itemSelect)
        except:
            print("[Error] input for --select has to be one specific and valid item value (see --list)")
            sys.exit()
        file = parsedIso.root.children[itemSelectint]
        fileName = file.name.decode('utf-8')
        fileContent = file.content
        saveFile(fileName, fileContent, outFolder)

def isoExtractstdout(parsedIso, itemSelect):
    # function to dump file content to stdout
    file = parsedIso.root.children[itemSelect]
    fileContent = file.content
    try:
        sys.stdout.buffer.write(fileContent)
    except:
        pass

def isoList(parsedIso):
    # function to list content of root directory
    rootFiles = list()
    fileCount = 0
    for file in parsedIso.root.children:
        fileInfo = list()
        fileName = file.name.decode('utf-8')
        fileSize = str(file.length)
        fileHeader = file.content[0:10].hex()
        fileMD5 = hashlib.md5(file.content).hexdigest()
        fileSha256 = hashlib.sha256(file.content).hexdigest()
        fileInfo.append(str(fileCount))
        fileInfo.append(fileName)
        fileInfo.append(fileSize)
        fileInfo.append(fileHeader)
        fileInfo.append(fileMD5)
        fileInfo.append(fileSha256)
        rootFiles.append(';'.join(str(x) for x in fileInfo))
        fileCount += 1

    if len(rootFiles) >= 1:
        return rootFiles

def isoListprint(rootFiles):
    print("Index" + ";" + "Name" + ";" + "Size" + ";" + "Header" + ";" + "MD5" + ";" + "SHA256")
    for item in rootFiles:
        print(item)

def isoMetadata(parsedIso):
    # function to show iso metadata
    metaData = dict()
    metaData['volume name'] = parsedIso.volume_descriptors.get("primary").volume_identifier.decode('utf-8')
    metaData['volume block count'] = parsedIso.volume_descriptors.get("primary").volume_space_size
    metaData['volume block size'] = parsedIso.volume_descriptors.get("primary").logical_block_size
    metaData['voulme size'] = metaData['volume block count'] * metaData['volume block size']
    metaData['volume set name'] = parsedIso.volume_descriptors.get("primary").volume_set_identifier.decode('utf-8')
    metaData['volume software'] = parsedIso.volume_descriptors.get("primary").application_identifier.decode('utf-8')
    metaData['volume create root dir'] = parsedIso.root.datetime
    metaData['volume create volume'] = parsedIso.volume_descriptors.get("primary").volume_datetime_created.decode('cp437')
    metaData['volume modify'] = parsedIso.volume_descriptors.get("primary").volume_datetime_modified.decode('cp437')

    for key, value in metaData.items():
        print(key + " = " + str(value))

def saveFile(fileName, fileContent, outFolder):
    # generic function to dump files
    fullPath = os.path.join(outFolder + fileName)
    with open(fullPath, 'wb') as fileHandle:
        fileHandle.write(fileContent)
        fileHandle.close()

def main():
    # check platform and set working directory for dump output
    cwd = os.getcwd()
    if platform.system() == 'Windows':
        workDir = cwd + '\\'''
    elif platform.system() == 'Darwin':
        workDir = cwd + '/'
    elif platform.system() == 'Linux':
        workDir = cwd + '/'
    else:
        workDir = '.'

    # script arguments
    parser = argparse.ArgumentParser(prog="isodump.py", usage="%(prog)s -i <file> [options]", description="ISO dump utility")
    parser.add_argument("-d", "--dump", help="dump file (default: item 0 to stdout)", action="store_true")
    parser.add_argument("-i", "--iso", help="iso file to analyze")
    parser.add_argument("-l", "--list", help="List all files from root directory (csv output)", action="store_true")
    parser.add_argument("-M", "--metadata", help="Print metadata", action="store_true")
    parser.add_argument("-o", "--out", help="output folder (default: current working directory)", nargs='?', type=str, const=workDir)
    parser.add_argument("-s", "--select", help="select item nr for dumping (a for all)", nargs='?', type=str, const='0')
    parser.add_argument("--version", help="show program's version number and exit", action="version", version='%(prog)s v0.1')
    args = parser.parse_args()

    isoFile = args.iso
    outFolder = args.out
    itemSelect = args.select

    # input check
    if not (args.iso):
            parser.error("argument -i ISO is mandatory!")

    # function to dump files
    if args.dump:
        if not args.iso:
            parser.error("argument -i ISO is mandatory!")
        else:
            if not args.out and not args.select:
                itemSelect = 0
                checkFile(isoFile)
                isoExtractstdout(isoAnalyzer(isoFile), itemSelect)
            elif not args.out and args.select:
                try:
                    itemSelect = int(args.select)
                except:
                    parser.error("file dump to stdout only works with one item")
                checkFile(isoFile)
                isoExtractstdout(isoAnalyzer(isoFile), itemSelect)
            elif args.out and not args.select:
                if not os.path.exists(outFolder):
                    os.makedirs(outFolder)
                itemSelect = 0
                isoExtract(isoAnalyzer(isoFile), outFolder, itemSelect)
            elif args.out and args.select:
                if not os.path.exists(outFolder):
                    os.makedirs(outFolder)
                checkFile(isoFile)
                isoExtract(isoAnalyzer(isoFile), outFolder, itemSelect)
    if args.out and not args.dump:
        parser.error("argument --out only works with --dump")
    if args.select and not args.dump:
        parser.error("argument --select only works with --dump.")

    # function to show file metadata
    if args.list:
        if not args.iso:
            parser.error("argument -i ISO is mandatory!")
        else:
            checkFile(isoFile)
            fileList = isoList(isoAnalyzer(isoFile))
            isoListprint(fileList)

    # function to show iso metadata
    if args.metadata:
        if not args.iso:
            parser.error("argument -i ISO is mandatory!")
        else:
            checkFile(isoFile)
            isoMetadata(isoAnalyzer(isoFile))

if __name__ == "__main__":
    main()
