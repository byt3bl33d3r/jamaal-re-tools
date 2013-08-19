# Buttplug.py: detect if your workstation is running off AC or Battery (UPS) on Linux  
# requires: upower and python-daemon
# http://www.wiebetech.com/products/HotPlug.php
# sudo python buttplug.py start 

import time
import subprocess

import os.path
try:
    os.path.isfile("/usr/bin/upower")
except:
    print "upower missing: sudo apt-get install upower"  
    sys.exit()
    

try:
    from daemon import runner 
    has_daemon = True
except ImportError:
    has_daemon = False 
    print "install https://pypi.python.org/pypi/python-daemon/"
    print "sudo apt-get install python-deamon"
    sys.exit()

class App():
    def __init__(self):
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/tty'
        self.stderr_path = '/dev/tty'
        self.pidfile_path =  '/tmp/buttplug.pid'
        self.pidfile_timeout = 5
    def run(self):
        while True:
            subproc_handle = subprocess.Popen(["/usr/bin/upower","-d"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            outstr = subproc_handle.communicate()
            batterStr = outstr[0].find("on-battery:")
            presentStr = outstr[0][batterStr:]
            presentVal = presentStr[:presentStr.find("\n")]
            if "yes" in presentVal:
                # UPS Device detected, call your clean up crew here 
                # Example: rm important data,  urandom hd, encrypt important stuff shutdownbox...
                # subproc_handle = subprocess.Popen(["/bin/rm","-rf", "/h4gis"],stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
                # subproc_handle = subprocess.Popen(["/sbin/shutdown","-h","now"],stdout=subprocess.PIPE, stderr=subprocess.PIPE)                
                print "Eazy-E - F.T.P"
            else:
                # test every minute: syslog, email ok status 
                # print "DEBUG: AC-POWER CONNECTED" 
                time.sleep(60)
                pass 

app = App()
daemon_runner = runner.DaemonRunner(app)
daemon_runner.do_action()

    
