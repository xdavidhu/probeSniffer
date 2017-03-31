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

try:
    arg1 = sys.argv[1]
except:
    arg1 = ""
    
try:
    arg2 = sys.argv[2]
except:
    arg2 = ""

if arg1 == "":
    print("[!] Usage: sudo python3 probeSniffer.py <INTERFACE> <ARGUMENTS>\n    Use -h for help.")
    exit()

if arg1 == "-h" or arg1 == "--help" or arg1 == "-H" or arg2 == "-h" or arg2 == "--help" or arg2 == "-H":
    print("Usage: sudo python3 probeSniffer.py <INTERFACE> <ARGUMENTS>\n\nOptions:\n       -d = Show duplicate requests\n  --nosql = Disable SQL logging completely")
    exit()

showDuplicates = False
noSQL = False
alreadyStopping = False

#DEBUG MODE - At your own risk ;)
debugMode = False

if arg2 == "--nosql":
    noSQL = True
elif arg2 == "-D" or arg2 == "-d":
    showDuplicates = True
elif arg2 != "":
    print("[!] Argument " + arg2 + " not known. Type -h for help.")
    exit()


print(" ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____    \n" +
      "|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \   \n" +
      "|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )  \n" +
      "|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /   \n" +
      "|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \   \n" +
      "|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \  \n" +
      "|__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__| \n" +
      "                                                       2.0 by @xdavidhu \n")

script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

monitor_iface = arg1

if noSQL:
    print("[I] NO-SQL MODE!\n")
if showDuplicates:
    print("[I] Showing duplicates...\n")

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
                os.system("iwconfig " + monitor_iface + " channel " + str(channel))
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
    if not nossid:
        try:
            debug("sql duplicate check started")
            if not noSQL:
                if not checkSQLDuplicate(ssid, mac_address):
                    debug("not duplicate")
                    debug("saving to sql")
                    saveToMYSQL(mac_address, vendor, ssid)
                    debug("saved to sql")
                    print(print_source + " (" + vendor + ")  ==> '" + ssid + "'")
                else:
                    if showDuplicates:
                        debug("duplicate")
                        print("[D] " + print_source + " (" + vendor + ")  ==> '" + ssid + "'")
            else:
                print(print_source + " (" + vendor + ")  ==> '" + ssid + "'")
        except KeyboardInterrupt:
            stop()
            exit()
        except:
            pass
    else:
        print(print_source + " (" + vendor + ")  ==> BROADCAST")

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
        print(traceback.format_exc())
        pass

def checkSQLDuplicate(ssid, mac_add):
    try:
        debug("[1] checkSQLDuplicate called")
        cursor = SQLConncetor()
        cursor.execute("select count(*) from probeSniffer where ssid = ? and mac_address = ?", (ssid, mac_add))
        data = cursor.fetchall()
        data = str(data)
        debug("[2] checkSQLDuplicate data: " + str(data))
        if data == "[(0,)]":
            db.close()
            return False
        else:
            db.close()
            return True
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        debug("[!!!] CRASH IN checkSQLDuplicate")
        print(traceback.format_exc())
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
        print(traceback.format_exc())
        pass

def main():

    if not noSQL:
        print("[I] Setting up SQLite...")

        try:
            setupDB = sqlite3.connect("DB-probeSniffer.db")
        except:
            print("\n[!] Cant connect to database. Permission error?\n")
            exit()
        setupCursor = setupDB.cursor()
        setupCursor.execute("CREATE TABLE IF NOT EXISTS probeSniffer (mac_address VARCHAR(50),vendor VARCHAR(50),ssid VARCHAR(50),date VARCHAR(50))")
        setupDB.commit()
        setupDB.close()

    print("[I] Starting channelhopper in a new thread...")
    path = os.path.realpath(__file__)
    chopper = threading.Thread(target=chopping)
    chopper.daemon = True
    chopper.start()

    print("[I] Saving requests to 'DB-probeSniffer.db'")
    print("\n[I] Sniffing started... Please wait for requests to show up...\n")
    sniff(iface=monitor_iface, prn=PacketHandler)

    global alreadyStopping
    if not alreadyStopping:
        print("\n[I] Stopping...")
        if not noSQL:
            print("[I] Results saved to 'DB-probeSniffer.db'")
        print("\n[I] probeSniffer stopped.")

if __name__ == "__main__":
    main()
