*** A Guide for the New Honeypot User ***

# Now that I've installed the honeypot and got it working, what have I got?

1. Where is the API documentation? https://isc.sans.edu/api ?

1. Can I download all of my records (for a time period / overall) ?

1. What are all the places that show activity?

- sqlite DB of web requests
- cowlie record of SSH (and other) attempts
- FW alerting
- malware uploaded, ready for analysis
- commands used to interact

## What pieces are separate packages and what pieces are unique to the DShield package?

# The Honeypot in use

1. What have I contributed to DShield?

1. What kinds of analyses can I do with my DShield data?

1. What kinds of analyses can I do with my local data?

- Analyze cowrie data: /srv/cowrie/var/log/cowrie/{*.log*,*.json*}

     /srv/cowrie/var/log/cowrie

1. How does data my honeypot has seen now differ from what it's seen before?

1. What logs should I check to reassure myself that my honeypot has not been compromised?

1. Can my honeypot serve as a honeypot for my home network?

Is it true that the current firewall configuration seems to prevent activity from my own subnet from being logged by the honeypot?  I want to have my honeypot configured so if any IP from my network contacts it (except, perhaps, a fixed address), that it alerts, giving me an early warning of attacker behavior from within my network.  Can I do that?

[This answer needs research to create an answer.]


# Review the Cowrie logs

1. Useful aliases: For examples below we'll set variables for the database ("d"), files ("f"), and Cowrie logs ("l") directories.  Note if you've installed in non-standard locations you'll need to update these.

    d=/srv/www/DB
    
    f=/srv/cowrie/var/lib/cowrie/
    
    l=/srv/cowrie/var/log/cowrie

1. Using "logs" vs. "json" files - pros and cons

1. Find SSH conection strings

Here we look at the log previous to the current one (which is to say, the last log covering a full day):

    cd $l
    file=`ls -t cowrie.json*|head -2|tail -1`
    cat $file|jq '[ .src_ip, .eventid, (.message|if type == "array" then "Empty_Message_Field" else . end ) ]|join("|")'|less
    ls -t cowrie.json*|head -2|tail -1|jq '[ .src_ip, .eventid, .message ]|join("|")'|egrep -i 'remote ssh.*version'|less

Here we might look for any indications of attempts to break out of the honeypot.  (Anomalies, basically.)

    - "Cookie: mstshash=Administr" Seems to be a Microsoft bug that was silently patched, would truncate the mstshash value to 9 characters
    - Reference: https://www.loadbalancer.org/blog/microsoft-drops-support-for-mstshash-cookies/

2. Find the "data" field that's being sent in: (need to tweak to ignore "null")

    cd $l
    
    cat cowrie.json.2020-08-14|jq '.data?'|less

    - This might be executable instructions.  Needs to be analyzed.

    cd $l
    
    cat cowrie.json.2020-08-14|jq '[ .eventid?, .src_ip?, (.dst_port?|tostring) ]|join("|")'|egrep 'connect'|cut -d'|' -f 2-3|sort|uniq -c|less

# How do I find the logs that correspond to a downloaded file?  Who did it, and how?

    cd /srv/cowrie/var/log/cowrie

    - Check /srv/cowrie/var/log/cowrie in either json or log files for "download".  They show the mappings of source and filename to target file named for sha256sum of the input

    cd $l
    egrep -hi download cowrie.json*|jq '[ .outfile? , .url? , .destfile? ]|join("|")'|sort|uniq|less
    
# What usernames and passwords are being used against my honeypot?

    tail -f cowrie.json|jq '.|select(.eventid=="cowrie.login.failed")| [.timestamp[0:19], .eventid[7:], .src_ip, .username, .password, .message ]|join("|")'
        
    "2020-10-05T21:24:00|login.failed|39.109.115.192|root|Qwerty@3edc|login attempt [root/Qwerty@3edc] failed"                                                                      
    "2020-10-05T21:24:02|login.failed|140.143.25.149|root|ronaldo|login attempt [root/ronaldo] failed"                                                                              
    "2020-10-05T21:24:04|login.failed|164.132.145.70|root|QWE1231zxc|login attempt [root/QWE1231zxc] failed"                                                                        
    "2020-10-05T21:24:19|login.failed|5.182.39.88|root|letmein|login attempt [root/letmein] failed"                                                                                 
    "2020-10-05T21:24:28|login.failed|220.186.141.118|root|Password0123|login attempt [root/Password0123] failed"                                                                   
    "2020-10-05T21:24:39|login.failed|82.148.19.60|root|Pa$$w0rd[e]|login attempt [root/Pa$$w0rd[e]] failed"                                                                        
    "2020-10-05T21:24:42|login.failed|158.69.192.35|root|virus|login attempt [root/virus] failed"   

# What from the honeypot is uploaded to DShield and what is going to waste?

1. Are the malware samples that my system captures uploaded to DShield?  Are they available for me to retrieve?

1. Does the sqlite database ever get cleaned out?  Does it only increase in size?

1. Can we have the ERD for the sqlite database?  And an explanation of the tables?

1. Is the sqlite database part of Cowrie or separate?  Is the info in it duplicated in other logs or not?

    - Find that database here: /srv/www/DB

1. What sqlite queries are helpful for understanding what traffic has hit your honeypot?  You might consider three approaches for these queries:

    1. Which queries?
    1. Which attackers?
    1. Which target URIs?

    TABLES:
    FileResp      SQLResp       files         requests      useragents
    HdrResponses  Sigs          paths         responses
    RFIResp       XSSResp       postlogs      submissions


    .headers on
    select scriptreq, scriptresp from xssresp limit 20;

    select distinct path, ospath from paths limit 20;

    select distinct cmd, path, summary from requests limit 40;

    sqlite3 w3.sqlite 'select date, cmd, path, summary from requests limit 400;'|while read i j;do echo \`echo $i| perl -ne 'chomp;print scalar localtime($_);'\` $j;done

# What are queries I can do on the file downloads?

    find /srv/cowrie/var/lib/cowrie/downloads -type f -mtime -1

    find /srv/cowrie/var/lib/cowrie/downloads -type f -mtime -1|xargs file

That will list all the files downloaded to the system in the last 24-hour period.

# How do I watch the honeypot in real time?

- Approaches: tailing logs; sniffing traffic; periodic reporting

    cd $l
    
    tail -F cowrie.json|jq '[ .eventid, .message|.[0:45] ]|join(" +=+ ")'

    cd /var/log
    
    tail -F dshield.log|while read epoc rest;do echo `date -d"@$epoc"  +"%FT%T"` $rest;done

- Graphical / curses display approaches; exceeding device capabilities

- Offloading feeds to an analytical device (for power; for centralized access; for safety)

# Can I configure the honeypot, and how?

# I already installed the honeypot software, and my firewall blocks VNC, and I want to use RealVNC to connect to my Raspberry Pi.  What can I do?

Since you can only connect to the honeypot by using ssh to port 12222 (unless you configured it differently), you'll need to use port forwarding with ssh to tunnel the VNC connection to your honeypot.

Here's an example that worked using a honeypot that had IP 192.168.1.8:

    ssh -L 5900:192.168.1.8:5900 -p 12222 pi@192.168.1.8
    
One you've authenticated and are connected successfully, use VNC Connect (or another VNC tool) to make a direct connection to the Pi.

1. Open VNC
2. Connect to 127.0.0.1 (your loopback address).  You are connecting to your own system.  (Note: You should NOT have VNC server listening on port 5900 when you do this.  If you do, use a port other than 5900 as the first value of the -L parameter.)
3. You should connect to the pi.

If you are having issues, check the /var/log/vncserver-xll.log for useful troubleshooting hints.


## Reducing duplication of logging and artifact saving

## Changing retention time (logs, downloaded files)

## The honeypot seems primarily to simulate being a linux system.  Can I configure it to be a Windows system instead?

# If I want to contribute, what areas might need contributions?

1. Why are errors sent to root (see /var/spool/mail/root) regularly?

1. Can Cowrie be updated from using python2 to python3, since python2 is no longer supported?

1. What report might I create on a daily basis from my honeypot?

1. Can I automate checking downloaded executables with VirusTotal?

1. Are there any opportunities for breaking out of the honeypot sandbox?  What logs should I be checking?

    - Increasing integrity checking

1. Are there any opportunities for integrating full packet logging to enhance my honeypot findings?

1. Isolating my DMZ from my production segements

1. Enhancing/Adding TLS support

1. Incorporating the latest reported vulnerabilities

1. Emulating Windows devices/services

1. Emulating ICS/SCADA devices/services

1. Emulating IoT devices/services

1. Making one honeypot emulate multiple devices

1. Running more than one honeypot on the DMZ of one router

1. Maintaining a malware repository - safely

1. Consider what reporting is best retained in this document and what should be in a separate code document

1. Documentation!

1. Does Cowrie handle attempts differently if they are on the honeypot's port (12222 for most) than if other ports?

1. Why does my ssh connection to the honeypot close after a time?  Is the honeypot rebooting regularly?
