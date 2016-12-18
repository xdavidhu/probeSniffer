     ____  ____   ___  ____    ___ _________  ____ _____ _____  ___ ____    
    |    \|    \ /   \|    \  /  _/ ___|    \|    |     |     |/  _|    \   
    |  o  |  D  |     |  o  )/  [(   \_|  _  ||  ||   __|   __/  [_|  D  )  
    |   _/|    /|  O  |     |    _\__  |  |  ||  ||  |_ |  |_|    _|    /   
    |  |  |    \|     |  O  |   [_/  \ |  |  ||  ||   _]|   _|   [_|    \   
    |  |  |  .  |     |     |     \    |  |  ||  ||  |  |  | |     |  .  \  
    |__|  |__|\_|\___/|_____|_____|\___|__|__|____|__|  |__| |_____|__|\__| 
                                                           1.0 by @xdavidhu

<h3>Python program for sniffing unencrypted probe requests and logging them to MySQL.</h3>

# requirements:
  * Kali Linux / Raspbian with root privileges<br>
  * A wireless card, capable for monitor mode<br>
  * Python3 (probeSniffer will install the dependenices)
  
# downloading:
  <h3>"git clone https://github.com/xdavidhu/probeSniffer"</h3>
  
# starting:
  <h3>"sudo python3 probeSniffer.py [INTERFACE] [ARGUMENTS]"</h3>
  <h3> At the first run, probeSniffer will create a config file, named 'pS-config.cfg',<br>
       and it will ask you to enter your root MySQL credentials to that file!</h3>
  
# options:
  * <b>-d</b> / show duplicate requests (defaultly only new requests will be shown)
  * <b>--no-sql</b> / disable all MySQL functions (including duplicate checking/logging)
  * <b>-h</b> / display help menu

<h3> probeSniffer will save the results to database 'probeSnifferDB' -> table 'probeSniffer'! </h3>

# disclaimer:
  I'm not responsible for anything you do with this program, so please only use it for good and educational purposes.
