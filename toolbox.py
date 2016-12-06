#!/usr/bin/env python
#Author: Rajesh Majumdar
#All in One tool.

import os
from hackcolors import Style,Fore,Back,init
import urllib2
import sys
import ginputs
import ninputs

#Clearing Screen
if os.name == 'nt':
    os.system('cls')
else:
    os.system('clear')
    
def allinone():
    
    # -- Colors --
    green      = Style.BRIGHT+Fore.GREEN
    reset      = Style.RESET_ALL
    lightgreen = Fore.GREEN
    red        = Fore.RED
    boldred    = Style.BRIGHT+Fore.RED
    # -- Colors --
    
    print red+'-' * 60
    print lightgreen+"                   -----Hacker's ToolBox----"
    print green+'                   |  By: Rajesh Majumdar  |'
    print lightgreen+'                   -------------------------'
    print boldred+'                    Made with love in India.'
    print red+'-' * 60

    print reset+green+'''

 1. Information Gathering    8. Sniffing & Spoofing
 2. Vulnerability Analysis   9. Password Attacks
 3. Exploitation Tools      10. Maintaing Access
 4. Wireless Attacks        11. Hardware Hacking
 5. Forensics Tools         12. Reverse Engineering
 6. Web Application         13. Reporting Tools
 7. Stress Testing          14. Download all
 '''
    types = raw_input("\nFor what purpose you wanna download? > ")
    # Information Gathering 
    if types == '1':
        print '''
 1. Automater        16. SET
 2. Bing-IP2Hosts    17. SSLcAudit
 3. CaseFile         18. SSLStrip
 4. Cisco-Torch      19. SSLyze
 5. Cookie Cadger    20. theHarvester
 6. DNSEnum          21. TLSSLed
 7. DNSRecon         22. URLCrazy
 8. DNSTracer        23. WireShark
 9. Fierce           24. WOL-E
10. FragRouter       25. X-plico
11. Ghost Phisher    26. WebDigger
12. GooFile          27. Cloud-Buster
13. Miranda          28. Knock
14. nMap             29. Sublist3r
15. Recon-ng         30. Download All
'''
        tool = raw_input('\nEnter your option: ')
        # Each Tool
        if tool == '1':
            print '''
 Automater : It is a URL/domain, IP Address, and MD5
 Hash OSINT tool aimed at making the analysis process
 easier for intrusion Analysts. Given a target (URL,
  IP, or HASH) or a file full of targets. Automater
will return relevant results from sources like the f-
ollowing: IPvoid.com, Urlvoid.com, Labs.alienvault.com
, ThreatExpert, VxVault & VirusTotal

    Source: http://www.tekdefense.com/automater
    
    Author: TekDefense.com
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/1aN0rmus/TekDefense-Automater/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '2':
            print '''
Bing-IP2Hosts: Bing.com is a search engine owned by
Microsoft formely known as MSN Search & Live Search.
It has a unique feature to search for websites hosted
on a specific IP address. Bing-ip2hosts uses this fe-
ature to enumerate all hostnames which Bing has indexed
for a specific IP Address.

Source:
http://www.morningstarsecurity.com/research/bing-ip2hosts

Author: Andrew Horton
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://raw.githubusercontent.com/Strubbl/dotfiles/master/bin/bing-ip2hosts")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '3':
            print '''
CaseFile: It is a visual intelligence application that
can be used to determine the relatinships & real world
links between hundreds of different types of information

Source: http://paterva.com/web6/products/casefile.php

Author: Paterva
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://paterva.com/malv4/xl/MaltegoXL.v4.0.8.9247.deb")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '4':
            print '''
Cisco-Torch: Mass-Scanning, fingerprinting, and exploita-
tion tool was written while working on the next edition of
the "Hacking Exposed Cisco Networks". The main features
which makes it different from other tools is the extensive
use of forking to launch multiple scanning processes on the
background for maximum scanning efficiency.

Source: http://www.hackingciscoexposed.com/?link=tools

Author: Born by Arhont Team
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("http://www.hackingexposedcisco.com/tools/cisco-torch-0.4b.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)   
        elif tool == '5':
            print '''
Cookie Cadger: It helps identify information leakage from
applications that utilize insecure HTTP GET requests. It
is a graphical utility which harness the power of the Wir-
eShark suite & Java to provide a fully cross-platform, wh-
ich can monitor wired Ethernet, insecure Wi-Fi, or load a
packet capture file for offline analysis.

Source: https://www.cookiecadger.com/

Author: Matthew Sullivan
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("http://www.cookiecadger.com/files/CookieCadger-1.08.jar")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '6':
            print '''
DNSEnum: A multithreaded perl script to enumerate DNS in-
formation of a domain & to discover non-contigious ip
blocks.

Source: https://github.com/fwaeytens/dnsenum

Author: Filip Waeytens, tix tixxDZ
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/fwaeytens/dnsenum/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '7':
            print '''
DNSRecon: It provides the ability to perform:
    1. Check all NS Records for Zone transfers
    2. Enumerate General DNS Records for a given
       Domain (MX, SOA, NS, A, AAAA, SPF & TXT)
    3. Perform common SRV record enumeration.
       Top Level Domain (TLD) Expansion.
    4. Check for Wildcard Resolution

    and much more....

Source: https://www.github.com/darkoperator/dnsrecon

Author: Carlos Perez
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/fwaeytens/dnsenum/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '8':
            print '''
DNSTracer: It determines where a given Domain name Server
(DNS) get its information from a given hostname, and fol-
lows the chain of DNS servers back to the authorative an-
swer.

Source: http://www.mavetju.org/unix/general.php

Author: Edwin Groothius
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("http://www.mavetju.org/download/dnstracer-1.9.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '9':
            print '''
Fierce: It is meant specifically to locate likely targets
both inside and outside a corporate network. Only those
targets are listed. No exploitation is performed. It is a
reconnaissance tool. It is just a PERL scripttaht quickly
scans domains.

Source: http://ha.ckers.org/fierce/

Author: RSnake
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://github.com/davidpepper/fierce-domain-scanner/blob/master/fierce.pl")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '10':
            print '''
FragRouter: It is a network intrusin detection evasion
toolkit. It implements most of the attacks described in
the Secure Networks "Insertion, Evasion & Denial of
Service." IP Packets get sent from the attacker to the
fragrouter, which tranforms them into a fragmented data
stream to forward to the victim.

Source: fragRouter HomePage

Author: Dug Song, Anzen Computing
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://packetstormsecurity.com/files/download/15917/fragrouter-1.6.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '11':
            print '''
Ghost Phisher: It is a Wireless & Ethernet security audi-
ting & attack software program written using Python prog-
ramming Language and Python Qr GUI Library, the program
is able to emulate access points and deploy.

Source: https://code.google.com/p/ghost-phisher/

Author: Saviour Emmanuel Ekiko
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/savio-code/ghost-phisher/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '12':
            print '''
GooFile: Use this tool to search for a specific file
type in a given domain

Author: Thomas Richard
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/goofile/goofilev1.5.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '13':
            print '''
Miranda: It is a python based Universal Plug-n-Play
client application designed to discover, query and
interact with UPNP devices, particularly Internet
Gateway Devices (aka router). It can be used to au-
dit UPNP-enabled devices on a network for possible
vulnerabilities.

Source: https://code.google.com/p/mirandaupnptool/

Author: Craig Heffner
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/mirandaupnptool/miranda-1.0.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '14':
            print '''
nMap: (Network Mapper) is an utility for network discov-
ery & security auditing. Many systems and network admins
also find it useful for tasks such as network inventory
managing service upgrade schedules, and monitoring host
or service uptime.

Source: http://nmap.org/

Author: Fyodor
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://nmap.org/dist/nmap-7.31-setup.exe")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool  == '15':
            print '''
Recon-NG: It is a full-featured Web Reconnaissance
framework written in Python. Complete with indepe-
ndent modules, database interaction, built in con-
venience functions, interactive help and command
completion.

Source: https://bitbucket.org/LaNMaSteR53/recon-ng

Author: Tim Tomes
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://bitbucket.org/LaNMaSteR53/recon-ng/get/7723096ce230.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '16':
            print '''
SET: The Social Engineering Toolkit is an open source
penetration testing framework designed for Social-Eng
ineering. SET has a number of custom attack vectors
that allow you to make a believable attack in a fra-
ction of the time

Source:
https://github.com/trustedsec/social-engineering-toolkit

Author: David Kennedy, TrustedSec, LLC
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/trustedsec/social-engineering-toolkit/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '17':
            print '''
SSLcAudit: This tool is developed to automate testing
SSL/TLS clients for resistance against MiTM attacks.
It might be useful for testing a thick client, a mob-
ile application, an appliance, pretty much everything
communating over SSL/TLS over TCP.

Source:
http://www.gremwell.com/sites/default/files/sslcaudit/
doc/sslcaudit-user-guide-1.0.pdf

Author: Gremwell
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/grwl/sslcaudit/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '18':
            print '''
SSLStrip: It is a tool that transparently hijacks HTTP
traffic on a network, watch for HTTPS links and redir-
ects, and then map those links into look-alike HTTP
links or homograph-similar HTTPS links. It also supp-
orts modes for supplying a favicon which looks like a
lock icon, selective logging, and session denial.

Source: http://www.thoughtcrime.org/software/sslstrip/

Author: Moxie Marlinspike
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/moxie0/sslstrip/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '19':
            print '''
SSLyze: It is a python tool that can analyze the SSL
configuration of a server by connecting to it. It is
designed to be fast and comprehensive, and should he-
lp organizations and testors identify mis-configurat-
ions affecting their SSL servers.

Source: http://github.com/iSECPartners/sslyze

Author: iSECPartners
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/iSECPartners/sslyze/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '20':
            print '''
theHarvester: The objective of this program is to gather
emails, subdomains, hosts, employee names, open ports &
banners from different public sources like search engin-
es, PGP key servers & SHODAN computer database.

Source: http://code.google.com/p/theHarvester

Author: Christian Martorella
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/theharvester/theHarvester-2.2a.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '21':
            print '''
TLSSLed: It is a Linux shell script whose purpose is to
evalute the security of a target SSL/TLS web server imp-
lementation. It is based on sslscan, a through SSL/TLS
scanner that is based on the openssl library, and on
openssl_s_client command line tool.

Source: http://www.taddong.com/en/lab.html

Author: Raul Siles, Taddong SL
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://www.taddong.com/tools/TLSSLed_v1.3.sh")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '22':
            print '''
URLCrazy: It generates and test domain typos and variati-
ons to detect and perform typo squatting, URL hijacking,
phishing, and corporate espionage.

Source: http://morningstarsecurity.com/research/urlcrazy

Author: Andrew Horton
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://www.morningstarsecurity.com/downloads/urlcrazy-0.5.tar.gz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '23':
            print '''
WireShark: It is the world's foremost network protocol
analyzer. It lets you see what's happening on your net-
work at a microscopic level. It is the standard across
many industries and educational institues.

Source: http://www.wireshark.com/about.html

Author: Gerald Combs and Contributors
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://1.as.dl.wireshark.org/win64/Wireshark-win64-2.2.1.exe")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '24':
            print '''
WOL-E: It is a suite of tools of Wake on LAN features
of network attached computers, this is now enabled by
default on many Apple computers.

Source: https://code.google.com/p/wol-e/

Author: Nathaniel Carew
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/wol-e/wol-e-2.0.tar")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '25':
            print '''
X-plico: It extract from an internet traffic capture
the applications data contained. For e.g. from a pcap
file Xplico extracts each small (POP, IMAP & SMTP pr-
otocols), all HTTP content, each VoIP call, FTP, TFTP
and so on. Xplico is not a network protocol analyzer

Source: Xplico Homepage

Author: Gianluca Costa, Andre de Franceschi
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ninputs.Download("https://downloads.sourcefourge.net/project/xplico/Xplico%20versions/version%201.1.1/xplico-1.1.1.tgz")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '26':
            print '''
WebDigger: It is a python based tool, specially created
to get a company's unknown domain for pentestor.
Their are many domains of google, facebook, whatsapp etc.
which are not indexed in any search engines. And if you
try to ping them, the server will not respond. But the
server is still there and working. These domains are
specially created  for other works. for e.g. whatsapp.net
is not indexed anywhere, and if you ping this domain. You
will get an error. And this domain is used for communica-
tions between whatsapp users.

Source: https://rajeshmajumdar.github.io/

Author: Rajesh Majumdar
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/rajeshmajumdar/webdigger/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '27':
            print '''
Knock: It is a python tool designed to enumerate
subdomains on a target domain through a wordlist.

Source: https://www.github.com/guelfoweb

Author: GuelfoWeb
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/guelfoweb/knock/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '28':
            print '''
'''
        elif tool == '29':
            print '''
Sublist3r: It is a python tool that is designed to enu-
merate subdomains of a website using search engines. It
helps pentestors and bug hunters collect and gather
subdomains for the domain they are targeting.

Source: https://github.com/aboul3la

Author: Aboul3la
'''
            choice = raw_input('\nDo you want to download?(Y/N) > ').lower()
            if choice == 'y':
                ginputs.Download("https://github.com/aboul3la/Sublist3r/archive/master.zip")

            elif choice == 'n':
                allinone()

            else:
                sys.exit(1)
        elif tool == '30':
            ginputs.Download("https://github.com/1aN0rmus/TekDefense-Automater/archive/master.zip")
            ginputs.Download("https://github.com/aboul3la/Sublist3r/archive/master.zip")
            ginputs.Download("https://github.com/guelfoweb/knock/archive/master.zip")
            ginputs.Download("https://github.com/rajeshmajumdar/webdigger/archive/master.zip")
            ninputs.Download("https://downloads.sourcefourge.net/project/xplico/Xplico%20versions/version%201.1.1/xplico-1.1.1.tgz")
            ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/wol-e/wol-e-2.0.tar")
            ninputs.Download("https://1.as.dl.wireshark.org/win64/Wireshark-win64-2.2.1.exe")
            ninputs.Download("https://www.morningstarsecurity.com/downloads/urlcrazy-0.5.tar.gz")
            ninputs.Download("https://www.taddong.com/tools/TLSSLed_v1.3.sh")
            ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/theharvester/theHarvester-2.2a.tar.gz")
            ginputs.Download("https://github.com/iSECPartners/sslyze/archive/master.zip")
            ginputs.Download("https://github.com/moxie0/sslstrip/archive/master.zip")
            ginputs.Download("https://github.com/grwl/sslcaudit/archive/master.zip")
            ginputs.Download("https://github.com/trustedsec/social-engineering-toolkit/archive/master.zip")
            ginputs.Download("https://bitbucket.org/LaNMaSteR53/recon-ng/get/7723096ce230.zip")
            ninputs.Download("https://nmap.org/dist/nmap-7.31-setup.exe")
            ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/mirandaupnptool/miranda-1.0.tar.gz")
            ninputs.Download("https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/goofile/goofilev1.5.zip")
            ginputs.Download("https://github.com/savio-code/ghost-phisher/archive/master.zip")
            ninputs.Download("https://packetstormsecurity.com/files/download/15917/fragrouter-1.6.tar.gz")
            ninputs.Download("https://github.com/davidpepper/fierce-domain-scanner/blob/master/fierce.pl")
            ninputs.Download("http://www.mavetju.org/download/dnstracer-1.9.tar.gz")
            ginputs.Download("https://github.com/fwaeytens/dnsenum/archive/master.zip")
            ginputs.Download("https://github.com/fwaeytens/dnsenum/archive/master.zip")
            ninputs.Download("http://www.cookiecadger.com/files/CookieCadger-1.08.jar")
            ninputs.Download("http://www.hackingexposedcisco.com/tools/cisco-torch-0.4b.tar.gz")
            ninputs.Download("https://paterva.com/malv4/xl/MaltegoXL.v4.0.8.9247.deb")
            ninputs.Download("https://raw.githubusercontent.com/Strubbl/dotfiles/master/bin/bing-ip2hosts")
        else:
            allinone()
       #Vulnerability Analysis     
    elif types == '2':
        print '''
1. BED                    9. SidGuesser
2. Cisco-Global-Exploiter  10. SQLMap
3. DotDotPwn             11. SQLNinja
4. Hexorbase             12. SQLSus
5. Inguma                13. Powerfuzzer
6. Lynis                 14. Yersinia
7. Nmap                  15. PMD
8. OsScanner             16. SonarQube
'''
        tool = raw_input("\nEnter your option: ")
        if tool == '1':
            print '''
BED (Bruteforce Exploit Detector) It is a program designed
to check daemons for potential buffer overflows, format
string bugs etc.

Source: https://www.github.com/wireghoul/

Author: WireGhoul
'''
            choice = raw_input('\nDo you want to download?(Y/N)> ').lower()
            if choice == 'y':
                ginputs.Download("https://www.github.com/wireghoul/doona/archive/master.zip")
            elif choice == 'n':
                allinone()
            else:
                sys.exit(1)
        elif tool == '2':
            print '''
Cisco-Global-Exploiter: It is an advanced, simple
and fast security testing tool.

Source: https://www.github.com/foreni-packages

Author: Nemesis, E4m
'''
            choice = raw_input("\nDo you want to download?(Y/N)> ").lower()
            if choice == 'y':
                ginputs.Download("https://www.github.com/foreni-packages/cisco-global-exploiter/archive/master.zip")
            elif choice == 'n':
                allinone()
            else:
                sys.exit(1)
        elif tool == '3':
            print '''
DotDotPwn: It's a very flexible intelligent fuzzer to discover
transversal directory vulnerabilities in softwares such as HTTP/
FTP/TFTP servers, Web platforms such as CMSs, ERPs, Blogs etc.
Also it has a protocol-independent module to send the desired
payload to the host and the port specified.

Source: https://www.github.com/wireghoul/dotdotpwn

Author: chr1x, nitr0us
'''
            choice = raw_input("\nDo you want to download?(Y/N)> ").lower()
            if choice == 'y':
                ginputs.Download("https://www.github.com/wireghoul/dotdotpwn/archive/master.zip")
            elif choice == "n":
                allinone()
            else:
                sys.exit(1)
        elif tool == '4':
            print '''
Hexorbase: It is a database application designed for admin-
istering and auditing multiple database servers simultane-
ously from centralized location, It is capable of perfor-
ming SQL queries and bruteforce attacks against common
database servers. It also allows packet routing through proxies
or even metasploit pivoting antics to communicate with
remotely inaccessible servers which are hidden within local
subnets.

Source: https://code.google.com/p/hexorbase

Author: Saviour Emmanuel Ekiko
'''
            choice = raw_input("\nDo you want to download?(Y/N)> ").lower()
            if choice == 'y':
                ginputs.Download("https://www.github.com/savio-code/hexorbase/archive/master.zip")
            elif choice == "n":
                allinone()
            else:
                sys.exit(1)  
allinone()
