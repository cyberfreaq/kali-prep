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
