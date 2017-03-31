     ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____    
    |    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \   
    |  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )  
    |   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /   
    |  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \   
    |  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \  
    |__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__| 
                                           v2.0 by David Schütz (@xdavidhu)

<h3>A tool for sniffing unencrypted wireless probe requests from devices</h3>

# new in 2.0:
  * Logging to SQLite database file<br>
  * Settable nickname for mac addresses<br>
  * Options to filter output by mac address<br>
  * Capturing 'boradcast' probe requests (without ssid)<br>

# requirements:
  * Kali Linux / Raspbian with root privileges<br>
  * Python3 & PIP3 (probeSniffer will install the dependenices)<br>
  * A wireless card (capable for monitor mode) and one other internet connected interface (for vendor resolve)<br>

# options:
  * <b>-d</b> / do not show duplicate requests<br>
  * <b>-b</b> / do not show broadcast requests<br>
  * <b>--addnicks</b> /﻿add nicknames to mac addresses<br>
  * <b>--flushnicks</b> / flush nickname database<br>
  * <b>--nosql</b> / disable SQL logging completely<br>
  * <b>--debug</b> / turn debug mode on<br>
  * <b>-h</b> / display help menu<br>

# installing:

  <h3>Debian based systems:</h3>

```
$ sudo apt-get update && sudo apt-get install python3 python3-pip -y

$ git clone https://github.com/xdavidhu/probeSniffer

$ cd probeSniffer/

$ python3 -m pip install -r requirements.txt
```

  <h3>macOS / OSX:</h3>

```
$ brew install python3

$ git clone https://github.com/xdavidhu/probeSniffer

$ cd probeSniffer/

$ python3 -m pip install -r requirements.txt
```
**NOTE**: You need to have [Homebrew](http://brew.sh/) installed before running the macOS/OSX installation.<br>

# disclaimer:
  I'm not responsible for anything you do with this program, so please only use it for good and educational purposes.
