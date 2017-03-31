#!/usr/bin/env python3
# -.- coding: utf-8 -.-

import os
import time
import sys
import sqlite3
import threading
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import datetime
import urllib.request as urllib2
import argparse

parser = argparse.ArgumentParser(usage="probeSniffer.py interface [-h] [-d] [-b] [--nosql] [--addnicks] [--flushnicks] [--debug]")
parser.add_argument("interface", help='Interface (in monitor mode) for capturing the packets')
parser.add_argument("-d", action='store_true', help='do not show duplicate requests')
parser.add_argument("-b", action='store_true', help='do not show \'broadcast\' requests (without ssid)')
parser.add_argument("--nosql", action='store_true', help='disable SQL logging completely')
parser.add_argument("--addnicks", action='store_true', help='add nicknames to mac addresses')
parser.add_argument("--flushnicks", action='store_true', help='flush nickname database')
parser.add_argument("--debug", action='store_true', help='turn debug mode on')
if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

if args.d:
    showDuplicates = False
else:
    showDuplicates = True
if args.b:
    showBroadcasts = False
else:
    showBroadcasts = True
if args.nosql:
    noSQL = True
else:
    noSQL = False
if args.addnicks:
    addNicks = True
else:
    addNicks = False
if args.flushnicks:
    flushNicks = True
else:
    flushNicks = False
if args.debug:
    debugMode = True
else:
    debugMode = False

monitor_iface = args.interface

alreadyStopping = False

print(" ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____    \n" +
      "|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \   \n" +
      "|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )  \n" +
      "|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /   \n" +
      "|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \   \n" +
      "|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \  \n" +
      "|__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__| \n" +
      "                                        v2.0 by David Schütz (@xdavidhu)\n")

print("[W] Make sure to use an interface in monitor mode!\n")

script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False
if noSQL:
    externalOptionsSet = True
    print("[I] NO-SQL MODE!")
if showDuplicates == False:
    externalOptionsSet = True
    print("[I] Not showing duplicates...")
if showBroadcasts == False:
    externalOptionsSet = True
    print("[I] Not showing broadcasts...")
if externalOptionsSet:
    print()

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

if not noSQL:
    # nosql
    pass


def stop():
    global alreadyStopping
    debug("stoping called")
    if not alreadyStopping:
        debug("setting stopping to true")
        alreadyStopping = True
        print("\n[I] Stopping...")
        if not noSQL:
            print("[I] Results saved to 'DB-probeSniffer.db'")
        print("\n[I] probeSniffer stopped.")
        return

def debug(msg):
    if debugMode:
        print("[DEBUG] " + msg)

def chopping():
    while True:
        if not alreadyStopping:
            channel = 1
            while channel <= 12:
                os.system("iwconfig " + monitor_iface + " channel " + str(channel) + " > /dev/null 2>&1")
                debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " + "iwconfig " + monitor_iface + " channel " + str(channel))
                debug("[CHOPPER] HI I CHANGED CHANNEL TO " + str(channel))
                channel = channel + 1
                time.sleep(5)
        else:
            debug("[CHOPPER] IM STOPPING TOO")
            sys.exit()

def PacketHandler(pkt):
    debug("packethandler - called")
    try:
        if pkt.haslayer(Dot11):
            debug("packethandler - pkt.haslayer(Dot11)")
            if pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:
                debug("packethandler - if pkt.type")
                PrintPacket(pkt)
                debug("packethandler - printPacket called and done")
    except KeyboardInterrupt:
        debug("packethandler - keyboardinterrupt")
        stop()
        exit()
    except:
        debug("packethandler - exception")
        stop()
        exit()
        pass

def PrintPacket(pkt):
    debug("printpacket started")
    ssid = pkt.getlayer(Dot11ProbeReq).info.decode("utf-8")
    if ssid == "":
        nossid = True
        debug("no ssid in request... skipping")
        debug(str(pkt.addr2) + " " + str(pkt.addr1))
    else:
        nossid = False
    print_source = pkt.addr2
    url = "https://macvendors.co/api/vendorname/"
    # Mac address to lookup vendor from
    mac_address = print_source
    try:
        debug("url request started")
        request = urllib2.Request(url + mac_address, headers={'User-Agent': "API Browser"})
        response = urllib2.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        vendor = "No Vendor (INTERNET ERROR)"
    debug("vendor request done")
    nickname = getNickname(print_source)
    if not nossid:
        try:
            debug("sql duplicate check started")
            if not noSQL:
                if not checkSQLDuplicate(ssid, mac_address):
                    debug("not duplicate")
                    debug("saving to sql")
                    saveToMYSQL(mac_address, vendor, ssid)
                    debug("saved to sql")
                    if nickname == False:
                        print(print_source + " (" + vendor + ")  ==> '" + ssid + "'")
                    else:
                        print(print_source + " [" + str(nickname) + "]" + " (" + vendor + ")  ==> '" + ssid + "'")
                else:
                    if showDuplicates:
                        debug("duplicate")
                        if nickname == False:
                            print("[D] " + print_source + " (" + vendor + ")  ==> '" + ssid + "'")
                        else:
                            print("[D] " + print_source + " [" + str(nickname) + "]" + " (" + vendor + ")  ==> '" + ssid + "'")
            else:
                if nickname == False:
                    print(print_source + " (" + vendor + ")  ==> '" + ssid + "'")
                else:
                    print(print_source + " [" + str(nickname) + "]" + " (" + vendor + ")  ==> '" + ssid + "'")
        except KeyboardInterrupt:
            stop()
            exit()
        except:
            pass
    else:
        if showBroadcasts:
            if nickname == False:
                print(print_source + " (" + vendor + ")  ==> BROADCAST")
            else:
                print(print_source + " [" + str(nickname) + "]" + " (" + vendor + ")  ==> BROADCAST")

def SQLConncetor():
    try:
        debug("sqlconnector called")
        global db
        db = sqlite3.connect("DB-probeSniffer.db")
        cursor = db.cursor()
        return cursor
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN SQLConncetor")
        debug(traceback.format_exc())
        pass

def checkSQLDuplicate(ssid, mac_add):
    try:
        debug("[1] checkSQLDuplicate called")
        cursor = SQLConncetor()
        cursor.execute("select count(*) from probeSniffer where ssid = ? and mac_address = ?", (ssid, mac_add))
        data = cursor.fetchall()
        data = str(data)
        debug("[2] checkSQLDuplicate data: " + str(data))
        db.close()
        if data == "[(0,)]":
            return False
        else:
            return True
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN checkSQLDuplicate")
        debug(traceback.format_exc())
        pass

def saveToMYSQL(mac_add, vendor, ssid):
    try:
        debug("saveToMYSQL called")
        cursor = SQLConncetor()
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO probeSniffer VALUES (?, ?, ?, ?)", (mac_add, vendor, ssid, st))
        db.commit()
        db.close()
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN saveToMYSQL")
        debug(traceback.format_exc())
        pass

def setNickname(mac, nickname):
    debug("setNickname called")
    cursor = SQLConncetor()
    cursor.execute("INSERT INTO probeSnifferNicknames VALUES (?, ?)", (mac, nickname))
    db.commit()
    db.close()

def getNickname(mac):
    debug("getNickname called")
    cursor = SQLConncetor()
    cursor.execute("SELECT nickname FROM probeSnifferNicknames WHERE mac = ?", (mac,))
    data = cursor.fetchone()
    db.close()
    if data == None:
        return False
    else:
        data = data[0]
        data = str(data)
        return data


def main():
    global alreadyStopping

    if not noSQL:
        print("[I] Setting up SQLite...")

        try:
            setupDB = sqlite3.connect("DB-probeSniffer.db")
        except:
            print("\n[!] Cant connect to database. Permission error?\n")
            exit()
        setupCursor = setupDB.cursor()
        if flushNicks:
            try:
                setupCursor.execute("DROP TABLE probeSnifferNicknames")
                print("\n[I] Nickname database flushed.\n")
            except:
                print("\n[!] Cant flush nickname database, since its not created yet\n")
        setupCursor.execute("CREATE TABLE IF NOT EXISTS probeSniffer (mac_address VARCHAR(50),vendor VARCHAR(50),ssid VARCHAR(50),date VARCHAR(50))")
        setupCursor.execute("CREATE TABLE IF NOT EXISTS probeSnifferNicknames (mac VARCHAR(50),nickname VARCHAR(50))")
        setupDB.commit()
        setupDB.close()

    if addNicks:
        print("\n[NICKNAMES] Add nicknames to mac addresses.")
        while True:
            print()
            mac = input("[?] Mac address: ")
            if mac == "":
                print("[!] Please enter a mac address.")
                continue
            nick = input("[?] Nickname for mac '" + str(mac) + "': ")
            if nick == "":
                print("[!] Please enter a nickname.")
                continue
            setNickname(mac, nick)
            addAnother = input("[?] Add another nickname? Y/n: ")
            if addAnother.lower() == "y" or addAnother == "":
                pass
            else:
                break

    print("[I] Starting channelhopper in a new thread...")
    path = os.path.realpath(__file__)
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()
    print("[I] Saving requests to 'DB-probeSniffer.db'")
    print("\n[I] Sniffing started... Please wait for requests to show up...\n")
    try:
        sniff(iface=monitor_iface, prn=PacketHandler)
    except KeyboardInterrupt:
        pass
    except OSError:
        alreadyStopping = True
        print("[!] An error occurred. Debug:")
        print(traceback.format_exc())
        print("\n[I] probeSniffer stopped.")
        exit(1)

    if not alreadyStopping:
        print("\n[I] Stopping...")
        if not noSQL:
            print("[I] Results saved to 'DB-probeSniffer.db'")
        print("\n[I] probeSniffer stopped.")

if __name__ == "__main__":
    main()
