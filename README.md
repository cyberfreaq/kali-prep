# kali-prep
Script to install tooling on a fresh Kali image/snapshot

## Prerequisites
- Needs Kali image with ZSH
- Has to be run as root

## Installation  
### Fresh installation
  
**IMPORTANT**: Don't skip any of the installation steps. They are mandatory!  

Clone repo:  
```
cd /opt
git clone https://github.com/cyberfreaq/kali-prep.git
chmod +x /opt/kali-prep/kali-prep.zsh
```

Install kali-prep:
```
/opt/kali-prep/kali-prep.zsh -i
```

### Update existing installation
```
kali-prep.zsh -u
```

## Usage
### Recommended usage
Install base module once (basic packages and prerequisites for other tools):  
```
kali-prep -t base
```

Install the modules/tools you need:
- `-t`        install selected modules/tools
- `| tee ...` generate log file  

```
kali-prep -t external,web | tee /tmp/kali-prep.log
```

Check log:  
```
cat /tmp/kali-prep.log | more
```

### Other examples
Show help:  
```
kali-prep -h
```

List available modules/tools
```
kali-prep -l

# or shortcut "kan plan" (actually "kali-prep") 

kp
```
  
Install tools for int engagements plus ffuf:  
```
kali-prep -t int,ffuf
```
  
Dry-run with -w switch (What-If) - this prints out install messages without changing anything on your system:
```
kali-prep -t base,int,external -w
```

Print verbose messages:  
```
kali-prep -t base,int,external -v
```

# Available modules and tools
```
TOOLS                       MODULES                 FURTHER INFORMATION (workon venv | ~# cmd | path: path)
=========================   ====================    ========================================================
basics                      base                    apt-get -y install apt-transport-https bridge-utils \
                                                    build-essential dnsutils ethtool git-core golang jq \
                                                    net-tools nmap proxychains python3-pip telnet \
                                                    wireshark
docker                      base
go_env                      base                    Requires ZSH; Adds stuff to ~/.zshrc
open_vm_tools               -                       Not necessary when using official Kali VMware image
python2environment          base
virtualenvwrapper           base                    Requires ZSH; Adds stuff to ~/.zshrc

TOOLS                       MODULES                 FURTHER INFORMATION (workon venv | ~# cmd | path: path)
=========================   ====================    ========================================================
adidnsdump                  all, int
azure-cli                   all, azu
azure-stormspotter          -                       Not used during audits right now
bloodhound                  all, int
certipy                     all, int
cme-stable                  all, int                ~# crackmapexec
cme-latest                  -                       Kali already has the latest public version (~# cme)
empire                      -                       Original repo - not maintained anymore
empire30                    -                       New repo, but not used during audits right now
donpapi                     all, int           
eyewitness                  all, int
ffuf                        all, web
go-windapsearch             all, int
gobuster                    all, web
impacket-bleeding-edge      all, int                workon impacket
impacket-static-binaries    all, int                ~# getuserspns | ~# gettgt
invokemimikatz              all, int                path: /root/tools/Invoke-Mimikatz.ps1
kerbrute                    all, int
krbrelayx                   all, int                ~# addspn | ~# dnstool | ~# krbrelayx | ~# printerbug
ldaprelayscan               all, int           
masscan                     all, ext
maxpy                       all, int                ~# max
mitm6                       all, int
nikto                       -                       Not in use right now; Installs docker image.
nuclei                      all, web 
lsassy-and-procdump         all, int                ~# lsassy ... --procdump /root/tools/procdump/procdump.exe
pcredz                      all, int           
powerhub                    all, int                workon powerhub
printnightmare              all, int                workon printnightmare | ~# cve-2021-1675
pyfuscation                 -                       Not in use right now
pypykatz                    all, int 
rdp-sec-check               all, int 
responder-bleeding-edge     all, int                ~# responder-dev
roadrecon                   all, azu 
scoutsuite                  all, azu                workon scoutsuite
silentbridge                all, int 
sqlplus                     all, int
windapsearch                -                       Superseded by go-windapsearch
```

# Known issues
- Somewhere during the installation Kali asks for a password for a new "Default" keyring. I think this is caused by one of the tools from the azure module

# Roadmap
- [ ] Download https://github.com/NotSoSecure/password_cracking_rules/raw/master/OneRuleToRuleThemAll.rule
- [ ] Add a check if a tool is already installed
- [ ] Automatically activate and deactivate virtual environments when running a tool
- [ ] Add update routines for installed tools(?)
- [ ] Modularize script (folder "tools" with an entry per tool)
- [ ] Add jconsole
- [ ] Download and unzip Processhacker
- [ ] Install EyeWitness via apt?
- [ ] Configure Samba readonly and write shares
- [ ] Change /usr/local/bin links to 'python3 /opt/folder/tool.py "$@"' instead of 'cd /opt/folder/.....' to make sure that file parameters are working from the current directory
- [ ] Add https://github.com/saravana815/dhtest.git
- [ ] Add https://github.com/dirkjanm/PrivExchange
- [ ] Add zerologon_tester.py
- [ ] Add https://github.com/preempt/ntlm-scanner
  - Also consider this PR: https://github.com/preempt/ntlm-scanner/pull/1
