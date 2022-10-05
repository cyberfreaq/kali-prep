# kali-prep
Script to install tooling on a fresh Kali image/snapshot

## Prerequisites
- Needs Kali image with ZSH
- Has to be run as root

## Installation
```
cd /opt
git clone https://github.com/cyberfreaq/kali-prep.git
chmod +x /opt/kali-prep/kali-prep.zsh
/opt/kali-prep/kali-prep.zsh -i
```

**IMPORTANT**: Install base module (basic packages and prerequisites for other tools):  
```
kali-prep -t base
```

## Usage
### Recommended usage
- `-n`        suppresses usage warning
- `-t`        installs selected modules/tools
- `| tee ...` generates log file  

```
kali-prep -n -t external,web | tee /tmp/kali-prep.log
```

### Other examples
Show help:  
```
kali-prep -h
```
  
Install tools for internal engagements plus ffuf:  
```
kali-prep -t internal,ffuf
```
  
Dry-run with -w switch (What-If) - this prints out install messages without changing anything on your system:
```
kali-prep -t base,internal,external -w
```

Print verbose messages:  
```
kali-prep -t base,internal,external -v
```

# Available modules and tools
```
TOOLS                       MODULES                 FURTHER INFORMATION (workon: venv | ~# cmd | path: path)
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

TOOLS                       MODULES                 FURTHER INFORMATION (workon: venv | ~# cmd | path: path)
=========================   ====================    ========================================================
adidnsdump                  all, internal
azure-cli                   all, azure
azure-stormspotter          -                       Not used during audits right now
bloodhound                  all, internal
certipy                     all, internal
cme-stable                  all, internal           ~# crackmapexec
cme-latest                  -                       Kali already has the latest public version (~# cme)
empire                      -                       Original repo - not maintained anymore
empire30                    -                       New repo, but not used during audits right now
donpapi                     all, internal           
eyewitness                  all, internal
ffuf                        all, web
go-windapsearch             all, internal
gobuster                    all, web
impacket-bleeding-edge      all, internal           workon: impacket
impacket-static-binaries    all, internal           ~# getuserspns | ~# gettgt
invokemimikatz              all, internal           path: /root/tools/Invoke-Mimikatz.ps1
kerbrute                    all, internal
krbrelayx                   all, internal           ~# addspn | ~# dnstool | ~# krbrelayx | ~# printerbug
ldaprelayscan               all, internal           
masscan                     all, external
maxpy                       all, internal           ~# max
mitm6                       all, internal
nikto                       -                       Not in use right now; Installs docker image.
nuclei                      all, web 
lsassy-and-procdump         all, internal           ~# lsassy ... --procdump /root/tools/procdump/procdump.exe
pcredz                      all, internal           
powerhub                    all, internal           workon: powerhub
printnightmare              all, internal           workon: printnightmare | ~# cve-2021-1675
pyfuscation                 -                       Not in use right now
pypykatz                    all, internal 
rdp-sec-check               all, internal 
responder-bleeding-edge     all, internal           ~# responder-dev
roadrecon                   all, azure 
scoutsuite                  all, azure              workon: scoutsuite
silentbridge                all, internal 
sqlplus                     all, internal
windapsearch                -                       Superseded by go-windapsearch
```

# Known issues
- "printf" and "read" command appear in wrong order in the warning message when running the script
- Somewhere during the installation Kali asks for a password for a new "Default" keyring
  - Workaround: apt -y install seahorse; open application "Passwords and Keys" and create new "Password Keyring" with name "Default" (choose any pw you like)

## Todo
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
