#!/usr/bin/env python3
# -.- coding: utf-8 -.-

try:
    import os
    import sys
    import time
    import json
    import pyshark
    import sqlite3
    import datetime
    import argparse
    import threading
    import urllib.request as urllib2
except KeyboardInterrupt:
    print("\n[I] Stopping...")
    raise SystemExit
except:
    print("[!] Failed to import the dependencies... " +\
            "Please make sure to install all of the requirements " +\
            "and try again.")
    raise SystemExit

parser = argparse.ArgumentParser(
    usage="probeSniffer.py [monitor-mode-interface] [options]")
parser.add_argument(
    "interface", help='interface (in monitor mode) for capturing the packets')
parser.add_argument("-d", action='store_true',
                    help='do not show duplicate requests')
parser.add_argument("-b", action='store_true',
                    help='do not show \'broadcast\' requests (without ssid)')
parser.add_argument("-a", action='store_true',
                    help='save duplicate requests to SQL')
parser.add_argument("--filter", type=str,
                    help='only show requests from the specified mac address')
parser.add_argument('--norssi', action='store_true',
                    help="include rssi in output")
parser.add_argument("--nosql", action='store_true',
                    help='disable SQL logging completely')
parser.add_argument("--addnicks", action='store_true',
                    help='add nicknames to mac addresses')
parser.add_argument("--flushnicks", action='store_true',
                    help='flush nickname database')
parser.add_argument('--noresolve', action='store_true',
                    help="skip resolving mac address")
parser.add_argument("--debug", action='store_true', help='turn debug mode on')

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
showDuplicates = not args.d
showBroadcasts = not args.b
noSQL = args.nosql
addNicks = args.addnicks
flushNicks = args.flushnicks
debugMode = args.debug
saveDuplicates = args.a
filterMode = args.filter != None
norssi = args.norssi
noresolve = args.noresolve
if args.filter != None:
    filterMac = args.filter

monitor_iface = args.interface
alreadyStopping = False


def restart_line():
    sys.stdout.write('\r')
    sys.stdout.flush()


def statusWidget(devices):
    if not filterMode:
        sys.stdout.write("Devices found: [" + str(devices) + "]")
    else:
        sys.stdout.write("Devices found: [FILTER MODE]")
    restart_line()
    sys.stdout.flush()


header = """
 ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____
|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \\
|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )
|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /
|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \\
|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \\
|__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__|
"""

try:
    print(header + "                                       v3.0 by David Schütz (@xdavidhu)\n")
except:
    print(header + "                                                      v3.0 by @xdavidhu\n")

print("[W] Make sure to use an interface in monitor mode!\n")

devices = []
script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

externalOptionsSet = False
if noSQL:
    externalOptionsSet = True
    print("[I] NO-SQL MODE!")
if not showDuplicates:
    externalOptionsSet = True
    print("[I] Not showing duplicates...")
if not showBroadcasts:
    externalOptionsSet = True
    print("[I] Not showing broadcasts...")
if filterMode:
    externalOptionsSet = True
    print("[I] Only showing requests from '" + filterMac + "'.")
if saveDuplicates:
    externalOptionsSet = True
    print("[I] Saving duplicates to SQL...")
if norssi:
    externalOptionsSet = True
    print("[I] Not showing RSSI values...")
if noresolve:
    externalOptionsSet = True
    print("[I] Not resolving MAC addresses...")
if debugMode:
    externalOptionsSet = True
    print("[I] Showing debug messages...")
if externalOptionsSet:
    print()

print("[I] Loading MAC database...")
with open(script_path + "oui.json", 'r') as content_file:
    obj = content_file.read()
resolveObj = json.loads(obj)

def stop():
    global alreadyStopping
    debug("stoping called")
    if not alreadyStopping:
        debug("setting stopping to true")
        alreadyStopping = True
        print("\n[I] Stopping...")
        if not noSQL:
            print("[I] Results saved to 'DB-probeSniffer.db'")
        print("[I] probeSniffer stopped.")
        raise SystemExit


def debug(msg):
    if debugMode:
        print("[DEBUG] " + msg)


def chopping():
    while True:
        if not alreadyStopping:
            channels = [1, 6, 11]
            for channel in channels:
                os.system("iwconfig " + monitor_iface + " channel " +
                          str(channel) + " > /dev/null 2>&1")
                debug("[CHOPPER] HI IM RUNNING THIS COMMAND: " +
                      "iwconfig " + monitor_iface + " channel " + str(channel))
                debug("[CHOPPER] HI I CHANGED CHANNEL TO " + str(channel))
                time.sleep(5)
        else:
            debug("[CHOPPER] IM STOPPING TOO")
            sys.exit()

def resolveMac(mac):
    try:
        global resolveObj
        for macArray in resolveObj:
            if macArray[0] == mac[:8].upper():
                return macArray[1]
        return "RESOLVE-ERROR"
    except:
        return "RESOLVE-ERROR"

def packetHandler(pkt):
    statusWidget(len(devices))
    debug("packetHandler started")

    nossid = False
    if not str(pkt.wlan_mgt.tag) == "Tag: SSID parameter set: Broadcast":
        ssid = pkt.wlan_mgt.ssid
    else:
        nossid = True

    rssi_val = pkt.radiotap.dbm_antsignal
    mac_address = pkt.wlan.ta
    bssid = pkt.wlan.da

    if not noresolve:
        debug("resolving mac")
        vendor = resolveMac(mac_address)
        debug("vendor query done")
    else:
        vendor = "RESOLVE-OFF"
    inDevices = False
    for device in devices:
        if device == mac_address:
            inDevices = True
    if not inDevices:
        devices.append(mac_address)
    nickname = getNickname(mac_address)
    if filterMode:
        if mac_address != filterMac:
            return
    if not nossid:
        try:
            debug("sql duplicate check started")
            if not noSQL:
                if not checkSQLDuplicate(ssid, mac_address, bssid):
                    debug("not duplicate")
                    debug("saving to sql")
                    saveToMYSQL(mac_address, vendor, ssid, rssi_val, bssid)
                    debug("saved to sql")
                    if not noresolve:
                        print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + " (" + vendor + ")" + (" [" + str(rssi_val) + "]" if not norssi else "") +  " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
                    else:
                        print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + (" [" + str(rssi_val) + "]" if not norssi else "") +  " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
                else:
                    if saveDuplicates:
                        debug("saveDuplicates on")
                        debug("saving to sql")
                        saveToMYSQL(mac_address, vendor, ssid, rssi_val)
                        debug("saved to sql")
                    if showDuplicates:
                        debug("duplicate")
                        if not noresolve:
                            print("[D] " + mac_address + (" [" + str(nickname) + "]" if nickname else "") + " (" + vendor + ")" + (" [" + str(rssi_val) + "]" if not norssi else "")  + " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
                        else:
                            print("[D] " + mac_address + (" [" + str(nickname) + "]" if nickname else "") + (" [" + str(rssi_val) + "]" if not norssi else "")  + " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
            else:
                if not noresolve:
                    print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + " (" + vendor + ")" + (" [" + str(rssi_val) + "]" if not norssi else "") + " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
                else:
                    print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + (" [" + str(rssi_val) + "]" if not norssi else "") + " ==> '" + ssid + "'" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
        except KeyboardInterrupt:
            stop()
            exit()
        except:
            pass
    else:
        if showBroadcasts:
            if not noresolve:
                print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + " (" + vendor + ")" + (" [" + str(rssi_val) + "]" if not norssi else "") + " ==> BROADCAST" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
            else:
                print(mac_address + (" [" + str(nickname) + "]" if nickname else "") + (" [" + str(rssi_val) + "]" if not norssi else "") + " ==> BROADCAST" + (" [BSSID: " + str(bssid) + "]" if not bssid == "ff:ff:ff:ff:ff:ff" else ""))
    statusWidget(len(devices))


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


def checkSQLDuplicate(ssid, mac_add, bssid):
    try:
        debug("[1] checkSQLDuplicate called")
        cursor = SQLConncetor()
        cursor.execute(
            "select count(*) from probeSniffer where ssid = ? and mac_address = ? and bssid = ?", (ssid, mac_add, bssid))
        data = cursor.fetchall()
        data = str(data)
        debug("[2] checkSQLDuplicate data: " + str(data))
        db.close()
        return data != "[(0,)]"
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN checkSQLDuplicate")
        debug(traceback.format_exc())


def saveToMYSQL(mac_add, vendor, ssid, rssi, bssid):
    try:
        debug("saveToMYSQL called")
        cursor = SQLConncetor()
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO probeSniffer VALUES (?, ?, ?, ?, ?, ?)", (mac_add, vendor, ssid,  st, rssi, bssid))
        db.commit()
        db.close()
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN saveToMYSQL")
        debug(traceback.format_exc())


def setNickname(mac, nickname):
    debug("setNickname called")
    cursor = SQLConncetor()
    cursor.execute(
        "INSERT INTO probeSnifferNicknames VALUES (?, ?)", (mac, nickname))
    db.commit()
    db.close()


def getNickname(mac):
    debug("getNickname called")
    cursor = SQLConncetor()
    cursor.execute(
        "SELECT nickname FROM probeSnifferNicknames WHERE mac = ?", (mac,))
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
                print(
                    "\n[!] Cant flush nickname database, since its not created yet\n")
        setupCursor.execute(
            "CREATE TABLE IF NOT EXISTS probeSniffer (mac_address VARCHAR(50),vendor VARCHAR(50),ssid VARCHAR(50), date VARCHAR(50), rssi INT, bssid VARCHAR(50))")
        setupCursor.execute(
            "CREATE TABLE IF NOT EXISTS probeSnifferNicknames (mac VARCHAR(50),nickname VARCHAR(50))")
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
    statusWidget(len(devices))

    while True:
        try:
            capture = pyshark.LiveCapture(interface=monitor_iface, bpf_filter='type mgt subtype probe-req')
            capture.apply_on_packets(packetHandler)
        except KeyboardInterrupt:
            stop()
        except:
            print("[!] An error occurred. Debug:")
            print(traceback.format_exc())
            print("[!] Restarting in 5 sec... Press CTRL + C to stop.")
            try:
                time.sleep(5)
            except:
                stop()

if __name__ == "__main__":
    main()
