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
- [ ] Download and unzip Processhacker
- [ ] Install EyeWitness via apt?
- [ ] Configure Samba readonly and write shares
- [ ] Change /usr/local/bin links to 'python3 /opt/folder/tool.py "$@"' instead of 'cd /opt/folder/.....' to make sure that file parameters are working from the current directory
- [ ] Add https://github.com/saravana815/dhtest.git
- [ ] Add https://github.com/dirkjanm/PrivExchange
- [ ] Add zerologon_tester.py
- [ ] Add https://github.com/preempt/ntlm-scanner
  - Also consider this PR: https://github.com/preempt/ntlm-scanner/pull/1
