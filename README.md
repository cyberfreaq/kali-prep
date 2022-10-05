# kali-prep
Script to install tooling on a fresh Kali image/snapshot

## Prerequisites
- Needs Kali image with ZSH
- Has to be run as root

## Installation
```
cd /opt
git clone git@github.com:cyberfreaq/kali-prep.git
chmod +x /opt/kali-prep/kali-prep.zsh
/opt/kali-prep/kali-prep.zsh -i
```

**IMPORTANT**: Install base module (basic packages and prerequisites for other tools):  
`kali-prep -t base`

## Usage
Show help:  
`kali-prep -h`  
  
Install tools for internal engagements plus ffuf:  
`kali-prep -t internal,ffuf`  
  
Dry-run with -w switch (What-If) - this prints out install messages without changing anything on your system:
`kali-prep -t base,internal,external -w`  

Print verbose messages:  
`kali-prep -t base,internal,external -v`  

# Known Issues
- "printf" and "read" command appear in wrong order in the warning message when running the script
- Somewhere during the installation Kali asks for a password for a new "Default" keyring
  - Workaround: apt -y install seahorse; open application "Passwords and Keys" and create new "Password Keyring" with name "Default" (choose any pw you like)

## Todo
- [ ] Add jconsole
- [X] Add https://github.com/cube0x0/CVE-2021-1675
- [X] Add https://github.com/byt3bl33d3r/ItWasAllADream
- [ ] Download and unzip Processhacker
- [ ] Install EyeWitness via apt?
- [ ] Configure Samba readonly and write shares
- [ ] Change /usr/local/bin links to 'python3 /opt/folder/tool.py "$@"' instead of 'cd /opt/folder/.....' to make sure that file parameters are working from the current directory
- [ ] Add nuclei
- [X] Add masscan from Repo
- [X] Add https://github.com/CBHue/PyFuscation
- [X] Add silentbridge
- [X] Add https://github.com/dirkjanm/krbrelayx
- [ ] Add https://github.com/saravana815/dhtest.git
- [X] Add https://github.com/knavesec/Max
- [ ] Add https://github.com/dirkjanm/PrivExchange
- [ ] Add zerologon_tester.py
- [ ] Add bloodhound 4.0
- [ ] install_bloodhound (): add neo4j Config to repo and download and replace (Listening on 0.0.0.0)
- [X] install_lsassy (): Download procdump to /root/tools/procdump
    - https://download.sysinternals.com/files/Procdump.zip
- [X] Add pypykatz
- [ ] Add https://github.com/preempt/ntlm-scanner
  - Also consider this PR: https://github.com/preempt/ntlm-scanner/pull/1
- [X] Add ScoutSuite
- [X] Add https://github.com/CiscoCXSecurity/rdp-sec-check
- [X] Add https://github.com/ropnop/go-windapsearch 
- [X] Add https://github.com/Azure/Stormspotter
- [X] Add roadrecon
