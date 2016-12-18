import os
import time
import sys
import linecache

try:
    if sys.argv[1] == "":
        print("[!] Usage: sudo python3 probeSniffer.py <INTERFACE> <ARGUMENTS>\n    Use -h for help.")
        exit()
except:
    print("[!] Usage: sudo python3 probeSniffer.py <INTERFACE> <ARGUMENTS>\n    Use -h for help.")
    exit()


if sys.argv[1] == "-h" or sys.argv[1] == "--help" or sys.argv[1] == "-H" or sys.argv[2] == "-h" or sys.argv[2] == "--help" or sys.argv[2] == "-H":
    print("Usage: sudo python3 probeSniffer.py <INTERFACE> <ARGUMENTS>\n\nOptions:\n       -d = Show duplicate requests\n  --nosql = Disable SQL logging completely")
    exit()

if sys.argv[1] == "chopping":
    while True:
        channel = 1
        while channel <= 12:
            os.system("iwconfig " + sys.argv[2] + " channel " + str(channel))
            print("Channel changed to " + str(channel))
            channel = channel + 1
            time.sleep(5)

global showDuplicates
showDuplicates = False
global noSQL
noSQL = False
global alreadyStopping
alreadyStopping = False

global debugMode

#DEBUG MODE - At your own risk ;)
debugMode = False


if sys.argv[2] == "--nosql":
    noSQL = True
elif sys.argv[2] == "-D" or sys.argv[2] == "-d":
    showDuplicates = True
else:
    print("[!] Argument " + sys.argv[2] + " not known. Type -h for help.")
    exit()


print(" ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____    \n" +
      "|    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \   \n" +
      "|  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )  \n" +
      "|   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /   \n" +
      "|  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \   \n" +
      "|  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \  \n" +
      "|__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__| \n" +
      "                                                       1.0 by @xdavidhu \n")

script_path = os.path.dirname(os.path.realpath(__file__))
script_path = script_path + "/"

if noSQL:
    print("[I] NO-SQL MODE!\n")
if showDuplicates:
    print("[I] Showing duplicates...\n")

print("[I] Installing/Updating dependencies...")

os.system("pip3 install pymysql > /dev/null 2>&1")
os.system("pip3 install scapy-python3 > /dev/null 2>&1")

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import pymysql
import datetime
import urllib.request as urllib2

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

if not noSQL:
    global sqlIP
    global sqlUser
    global sqlPass

    #CONFIG CREATION
    try:
        cfg = open(script_path+"pS-config.cfg", 'r')
    except:
        raw_conf = "#probeSniffer SQL config file - please enter root credentials\n\nSQL IP (localhost) = \nSQL User           = \nSQL Pass           = "
        os.system("sudo echo -e '" + raw_conf + "' > "+script_path+"pS-config.cfg")
        print("\n[!] Config file '"+script_path+"pS-config.cfg' created. Please\n    enter your SQL credentials, "
              "and start probeSniffer again...\n")
        exit()

    #GETTING THE CREDS FROM CONFIG
    sqlIP = linecache.getline(script_path+"pS-config.cfg", 3)
    sqlIP = sqlIP.replace("SQL IP (localhost) = ", "")
    sqlIP = sqlIP.replace("\n", "")
    if sqlIP == "":
        sqlIP = "localhost"

    sqlUser = linecache.getline(script_path+"pS-config.cfg", 4)
    sqlUser = sqlUser.replace("SQL User           = ", "")
    sqlUser = sqlUser.replace("\n", "")

    sqlPass = linecache.getline(script_path+"pS-config.cfg", 5)
    sqlPass = sqlPass.replace("SQL Pass           = ", "")
    sqlPass = sqlPass.replace("\n", "")


def stop():
    debug("stoping called")
    global alreadyStopping
    if not alreadyStopping:
        debug("setting stopping to true")
        alreadyStopping = True
        print("\n[I] Stopping...")
        os.system("sudo screen -S probeSniffer-chopping -X stuff '^C\n'")
        print("[I] Results saved to MySQL: 'probeSnifferDB' -> 'probeSniffer'")
        print("\n[I] probeSniffer stopped.")
        return

def debug(msg):
    if debugMode:
        print("[DEBUG] " + msg)

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
        debug("no ssid in request... skipping")
        return
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
        vendor = "No Vendor (ERROR)"
    debug("vendor request done")
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

def SQLConncetor():
    try:
        debug("sqlconnector called")
        global db
        db = pymysql.connect(sqlIP, sqlUser, sqlPass, "probeSnifferDB")
        cursor = db.cursor()
        return cursor
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        pass

def checkSQLDuplicate(ssid, mac_add):
    try:
        debug("checkSQLDuplicate called")
        cursor = SQLConncetor()
        cursor.execute("select count(*) from probeSniffer where ssid = %s and mac_address = %s", (ssid, mac_add))
        data = cursor.fetchall()
        data = str(data)
        if data == "((0,),)":
            db.close()
            return False
        else:
            db.close()
            return True
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        pass

def saveToMYSQL(mac_add, vendor, ssid):
    try:
        debug("saveToMYSQL called")
        cursor = SQLConncetor()
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("INSERT INTO probeSniffer VALUES (%s, %s, %s, %s)", (mac_add, vendor, ssid, st))
        db.commit()
        db.close()
    except KeyboardInterrupt:
        stop()
        exit()
    except:
        pass

def main():

    if not noSQL:
        print("[I] Setting up MySQL...")

        try:
            setupDB = pymysql.connect(sqlIP, sqlUser, sqlPass)
        except:
            print("\n[!] Cant connect/login to MySQL. Incorrect credentials?\n")
            exit()
        setupCursor = setupDB.cursor()
        setupCursor.execute("SET sql_notes = 0")
        setupCursor.execute("CREATE DATABASE IF NOT EXISTS probeSnifferDB")
        setupCursor.execute("CREATE TABLE IF NOT EXISTS probeSnifferDB.probeSniffer (mac_address VARCHAR(50),vendor VARCHAR(50),ssid VARCHAR(50),date VARCHAR(50))")
        setupCursor.execute("SET sql_notes = 1")
        setupDB.commit()
        setupDB.close()

    monitor_iface = sys.argv[1]
    print("[I] Setting '" + monitor_iface + "' to monitor mode...")
    os.system("ifconfig " + monitor_iface + " down; iwconfig " + monitor_iface + " mode monitor; ifconfig " + monitor_iface + " up")

    print("[I] Starting channelhopper in screen session...")
    path = os.path.realpath(__file__)
    os.system("screen -d -m -S probeSniffer-chopping python3 " + path + " chopping " + sys.argv[1])
    print("[I] Saving requests to MySQL: 'probeSnifferDB' -> 'probeSniffer'")
    print("\n[I] Sniffing started... Please wait for requests to show up...\n")
    sniff(iface=monitor_iface, prn=PacketHandler)

    global alreadyStopping
    if not alreadyStopping:
        print("\n[I] Stopping...")
        os.system("sudo screen -S probeSniffer-chopping -X stuff '^C\n'")
        print("[I] Results saved to MySQL: 'probeSnifferDB' -> 'probeSniffer'")
        print("\n[I] probeSniffer stopped.")

if __name__ == "__main__":
    main()
