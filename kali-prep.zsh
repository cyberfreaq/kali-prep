#!/bin/zsh

# load ~/.zshrc for mkvirtualenv
source ~/.zshrc

# predefine constants
CURRENT_TOOL=""
INSTALL_TOOL=0
LEFT_TO_DO=0
LEFT_TO_DO_MAXPY=0
LEFT_TO_DO_NEO4J=0
TAGS=()
TOOLNAME=$0
TOOLS=""
UPDATE_PREINSTALLED_REPOS=0
VERBOSE=0
WHATIF=0


## Color Coding
# https://www.shellhacks.com/bash-colors/

# NORMAL
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# BOLD
BLUEB='\033[1;34m'
YELLOWB='\033[1;33m'
REDB='\033[1;31m'
GREENB='\033[1;32m'


function usage {
        echo "Usage: $TOOLNAME [-t TOOLS] | tee kali-prep.log" 2>&1
        echo '*) Script for installing red team tooling'
        echo '*) Requires ZSH'
        echo ''
        echo '   -c          Clone PayloadsAllTheThings and SecLists to ~/tools'
        echo '   -h          Show this help message.'
        echo '   -i          Install this script to /opt/kali-prep and add "kali-prep" to /usr/local/bin'
        echo '   -l          List available tools.'
        echo '   -t TOOLS    Comma-separated list of modules and/or tools to install (e.g. -t base,ext,roadrecon).'
        echo '               *IMPORTANT*: The "base" module has to be installed at least once!'
        echo '   -u          Update kali-prep and other pre-installed repos (SecLists, PayloadsAllTheThings)'
        echo '   -v          Increase verbosity level.'
        echo '   -w          What if: Prints out install messages without installing anything (for troubleshooting purposes).'
        exit 1
}


function list_tools {
    echo '
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
impacket-bleeding-edge      all, int                workon impacket | ~# ntlmrelayx | ~# ...
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
'
    exit 1
}


function install_kali_prep {
    printf "${GREEN}[+] Installing kali-prep ... ${NC}\n"

    if [[ $WHATIF -eq 0 ]]; then
        echo 'Adding /usr/local/bin/kali-prep. You can call the script now with "kali-prep".'
        echo '#!/bin/zsh' > /usr/local/bin/kali-prep
        echo '/opt/kali-prep/kali-prep.zsh "$@"' >> /usr/local/bin/kali-prep
        chmod +x /usr/local/bin/kali-prep

        echo 'Adding shortcut for "kali-prep -l" to /usr/local/bin/kp.'
        echo '#!/bin/zsh' > /usr/local/bin/kp
        echo '/opt/kali-prep/kali-prep.zsh -l' >> /usr/local/bin/kp
        chmod +x /usr/local/bin/kp
    fi

    printf "${GREEN}[+] Installing kali-prep ... Done!${NC}\n"

    exit 1
}


function clone_repos {
    printf "${GREEN}[+] Cloning repositories ... ${NC}\n"

    if [[ $WHATIF -eq 0 ]]; then
        mkdir ~/tools
        cd ~/tools

        echo "  Cloning PayloadsAllTheThings to ~/tools/PayloadsAllTheThings ..."
        git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

        echo "  Cloning SecLists to ~/tools/SecLists..."
        git clone https://github.com/danielmiessler/SecLists.git
    fi

    echo "  Done!"

    exit 1
}


# if no input argument found, exit the script with usage
if [[ ${#} -eq 0 ]]; then
   usage
fi


# Parse arguments
while getopts chilt:uvw flag
do
    case "${flag}" in
        c)
            clone_repos
            ;;
        h)
	        usage
            ;;        
        i)
            install_kali_prep
	        ;;
        l)
            list_tools
            ;;
        t)
            # Split -t input parameter with delimiter ',' into an array
            IFS="," read -A TOOLS <<< ${OPTARG}
            echo ''
            echo "Tools to be installed: ${TOOLS[@]}"
            echo ''
            ;;
        u)
            UPDATE_PREINSTALLED_REPOS=1
            ;;
        v)
            VERBOSE=1
            ;;     
        w)
            WHATIF=1
            ;;
    esac
done


# Print verbose messages
function print_verbose {
   local MESSAGE="${@}"
   if [[ "${VERBOSE}" -eq 1 ]];then
      echo "${YELLOW}Verbose: ${MESSAGE}${NC}"
   fi
}


# Check if tool is to be installed
check_install_queue () {
    # Set install to 'No'
    INSTALL_TOOL=0
    
    print_verbose "===================== ${CURRENT_TOOL} ====================="
    for i in ${TAGS[@]}; do
        print_verbose "Checking pre-defined tag \"$i\" ..."
        for j in ${TOOLS[@]}; do
	        if [[ "$j" == "$i" ]]; then
	            INSTALL_TOOL=1
	            print_verbose "   [+] Pre-defined tag \"$i\" matches your input parameter \"$j\" - \"${CURRENT_TOOL}\" will be installed."
	        else
	            print_verbose "   [-] Pre-defined tag \"$i\" does not match your input parameter \"$j\"."
	        fi
        done
    done
}


###################
## Install TEMPLATE
###################

install_template () {
    CURRENT_TOOL="template"
    TAGS=("all" "<other>" "<modules>")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing <toolname> ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            ### install routine ###
        fi
    fi
}


########################################
## Install basic stuff and prerequisites
########################################


printf "${BLUEB}[i] Entering installation routine for base module ...${NC}\n"


install_basic_packages () {
    CURRENT_TOOL="basics"
    TAGS=("base")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing basic pkgs ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y install apt-transport-https bridge-utils \
            build-essential dnsutils ethtool git-core golang jq \
            net-tools nmap proxychains python3-pip telnet \
            wireshark 
        fi
    fi
}
install_basic_packages

# https://docs.docker.com/engine/install/debian/
# https://www.kali.org/docs/containers/installing-docker-on-kali/
install_docker () {
    CURRENT_TOOL="docker"
    TAGS=("base")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing docker ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            mkdir -p /etc/apt/keyrings
            apt-get remove docker docker-engine docker.io containerd runc
            apt-get -y install apt-transport-https ca-certificates curl gnupg-agent gnupg lsb-release software-properties-common
            curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
bullseye stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update
            apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
            systemctl enable docker
        fi
    fi
}
install_docker


setup_go_env () {
    CURRENT_TOOL="go_env"
    TAGS=("base")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Setting up go environment ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            echo '' >> ~/.zshrc
            echo '# Initialize go' >> ~/.zshrc
            echo 'export GOPATH=$HOME/go' >> ~/.zshrc
            echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc
            . ~/.zshrc
        fi
    fi
}
setup_go_env


install_open_vm_tools () {
    CURRENT_TOOL="open_vm_tools"
    TAGS=() # Not used in "base" module because official Kali VMware images have this pre-installed
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing open-vm-tools ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y libfuse-dev open-vm-tools-desktop fuse
        fi
    fi
}
install_open_vm_tools


install_python2environment () {
    CURRENT_TOOL="python2environment"
    TAGS=("base")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Python 2 environment ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /tmp
            wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
            python get-pip.py
            pip2 install --upgrade setuptools
            python -m pip install virtualenv
            
            # in order to not overwrite it when python3-pip is installed
            mv /usr/local/bin/virtualenv /usr/local/bin/virtualenvpy2 
        fi
    fi
}
install_python2environment


install_virtualenvwrapper () {
    CURRENT_TOOL="virtualenvwrapper"
    TAGS=("base")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing virtualenvwrapper ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            pip3 install virtualenvwrapper
            echo '' >> ~/.zshrc
            echo '# Initialize virtualenvwrapper' >> ~/.zshrc
            echo 'export WORKON_HOME=$HOME/.virtualenvs' >> ~/.zshrc
            echo 'export PROJECT_HOME=$HOME/Devel' >> ~/.zshrc
            echo 'export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3' >> ~/.zshrc
            echo 'export VIRTUALENVWRAPPER_VIRTUALENV=/usr/local/bin/virtualenv' >> ~/.zshrc
            echo 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.zshrc
            . ~/.zshrc
        fi
    fi
}
install_virtualenvwrapper


########################
## Install pentest stuff
########################


printf "${BLUEB}[i] Entering installation routine for pentesting tools (phase 1) ...${NC}\n"


# Install EyeWitness first because it clears the log
install_eyewitness () {
    CURRENT_TOOL="eyewitness"
    TAGS=("all" "azu")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then 
        printf "${GREEN}[+] Installing EyeWitness ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt update
            cd /opt
            git clone https://github.com/ChrisTruncer/EyeWitness.git
            cd EyeWitness/Python/setup
            ./setup.sh
            echo '#!/bin/bash' > /usr/local/bin/eyewitness
            echo 'cd /opt/EyeWitness/Python && ./EyeWitness.py "$@"' >> /usr/local/bin/eyewitness
            chmod +x /usr/local/bin/eyewitness
        fi
    fi
}
install_eyewitness


printf "${BLUEB}[i] Entering installation routine for pentesting tools (phase 2) ...${NC}\n"


install_adidnsdump () {
    CURRENT_TOOL="adidnsdump"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing adidnsdump ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            pip install git+https://github.com/dirkjanm/adidnsdump#egg=adidnsdump
        fi
    fi
}
install_adidnsdump


install_azure-cli () {
    CURRENT_TOOL="azure-cli"
    TAGS=("all" "azu")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing azure-cli ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y install azure-cli
        fi
    fi
}
install_azure-cli


install_azure_stormspotter () {
    CURRENT_TOOL="azure-stormspotter"
    TAGS=() # Not installed with any module because I don't use this tool right now
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Azure Stormspotter ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/Azure/Stormspotter
            cd Stormspotter
            docker-compose up --no-start
        fi
    fi
}
install_azure_stormspotter


install_bloodhound () {
    CURRENT_TOOL="bloodhound"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing bloodhound ...${NC}\n"
        LFET_TO_DO=1
        LEFT_TO_DO_NEO4J=1

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y install bloodhound
        fi
    fi
}
install_bloodhound


install_certipy () {
    CURRENT_TOOL="certipy"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Certipy ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/ly4k/Certipy.git
            cd Certipy
            python3 setup.py install
        fi
    fi
}
install_certipy


install_cme_latest () {
    CURRENT_TOOL="cme-latest"
    TAGS=() # Not installed with any module because Kali has the latest public version
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading latest CME release ...${NC}\n"
        
        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkdir cme
            cd cme
            wget 'https://github.com/byt3bl33d3r/CrackMapExec/releases/latest/download/cme-ubuntu-latest.4.zip'
            unzip cme-ubuntu-latest.4.zip
            chmod +x cme
            ln -s /opt/cme/cme /usr/local/bin/cme
        fi
    fi
}
install_cme_latest


install_cme_stable () {
    CURRENT_TOOL="cme-stable"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue
    
    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing CME stable ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y install crackmapexec
            echo "" >> ~/.cme/cme.conf
            echo "[BloodHound]" >> ~/.cme/cme.conf
            echo "bh_enabled=False" >> ~/.cme/cme.conf
        fi
    fi
}
install_cme_stable


install_donpapi () {
    CURRENT_TOOL="donpapi"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing DonPAPI ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/login-securite/DonPAPI.git
            cd DonPAPI
            python3 -m pip install -r requirements.txt
            echo '#!/bin/bash' > /usr/local/bin/donpapi
            echo 'cd /opt/DonPAPI/ && python3 DonPAPI "$@"' >> /usr/local/bin/donpapi
            chmod +x /usr/local/bin/donpapi
        fi
    fi
}
install_donpapi


install_empire () {
    CURRENT_TOOL="empire"
    TAGS=() # Original repo - not maintained anymore
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading Empire ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/EmpireProject/Empire.git
            echo '#!/bin/bash' > /usr/local/bin/empire
            echo 'cd /opt/Empire/ && ./empire "$@"' >> /usr/local/bin/empire
            chmod +x /usr/local/bin/empire
        fi
    fi
}
install_empire


install_empire_3.0 () {
    CURRENT_TOOL="empire30"
    TAGS=() # Not in use during audits right now
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Empire 3.0 docker container (~ 1 GB in size) ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            docker pull bcsecurity/empire:latest
            docker create -v empirevol:/empire --name empire bcsecurity/empire:latest
        fi
    fi
}
install_empire_3.0


install_ffuf () {
    CURRENT_TOOL="ffuf"
    TAGS=("all" "web")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing ffuf ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            go install github.com/ffuf/ffuf@latest
        fi
    fi
}
install_ffuf


install_go-windapsearch () {
    CURRENT_TOOL="go-windapsearch"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading @ropnop's latest go-windapsearch release ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkdir go-windapsearch
            cd go-windapsearch
            wget 'https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64'
            chmod +x windapsearch-linux-amd64
            ln -s /opt/go-windapsearch/windapsearch-linux-amd64 /usr/local/bin/windapsearch
        fi
    fi
}
install_go-windapsearch


install_gobuster () {
    CURRENT_TOOL="gobuster"
    TAGS=("all" "web")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing gobuster ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            go install github.com/OJ/gobuster/v3@latest
        fi
    fi
}
install_gobuster


install_impacket_bleeding_edge () {
    CURRENT_TOOL="impacket-bleeding-edge"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing impacket bleeding edge ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkvirtualenv impacket
            git clone https://github.com/SecureAuthCorp/impacket
            cd impacket
            pip install -r requirements.txt
            python setup.py build
            python setup.py install
            deactivate
        fi
    fi
}
install_impacket_bleeding_edge


install_impacket_static_binaries () {
    CURRENT_TOOL="impacket-static-binaries"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading some of @ropnop's latest stable impacket static binaries ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkdir impacket-static-binaries
            cd impacket-static-binaries
            wget 'https://github.com/ropnop/impacket_static_binaries/releases/latest/download/GetUserSPNs_linux_x86_64'
            wget 'https://github.com/ropnop/impacket_static_binaries/releases/latest/download/getTGT_linux_x86_64'
            chmod +x GetUserSPNs_linux_x86_64
            chmod +x getTGT_linux_x86_64
            ln -s /opt/impacket-static-binaries/GetUserSPNs_linux_x86_64 /usr/local/bin/getuserspns
            ln -s /opt/impacket-static-binaries/getTGT_linux_x86_64 /usr/local/bin/gettgt
        fi
    fi
}
install_impacket_static_binaries


install_kerbrute () {
    CURRENT_TOOL="kerbrute"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading @ropnop's latest kerbrute release ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkdir kerbrute
            cd kerbrute
            wget 'https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64'
            chmod +x kerbrute_linux_amd64
            ln -s /opt/kerbrute/kerbrute_linux_amd64 /usr/local/bin/kerbrute
        fi
    fi
}
install_kerbrute


install_krbrelayx () {
    CURRENT_TOOL="krbrelayx"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing krbrelayx.py ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/dirkjanm/krbrelayx
            cd krbrelayx
            chmod +x addspn.py dnstool.py krbrelayx.py printerbug.py
            echo '#!/bin/bash' > /usr/local/bin/addspn
            echo 'cd /opt/krbrelayx/ && python3 addspn.py "$@"' >> /usr/local/bin/addspn
            chmod +x /usr/local/bin/addspn
            echo '#!/bin/bash' > /usr/local/bin/dnstool
            echo 'cd /opt/krbrelayx/ && python3 dnstool.py "$@"' >> /usr/local/bin/dnstool
            chmod +x /usr/local/bin/dnstool
            echo '#!/bin/bash' > /usr/local/bin/krbrelayx
            echo 'cd /opt/krbrelayx/ && python3 krbrelayx.py "$@"' >> /usr/local/bin/krbrelayx
            chmod +x /usr/local/bin/krbrelayx
            echo '#!/bin/bash' > /usr/local/bin/printerbug
            echo 'cd /opt/krbrelayx/ && python3 printerbug.py "$@"' >> /usr/local/bin/printerbug
            chmod +x /usr/local/bin/printerbug
        fi
    fi
}
install_krbrelayx


install_ldaprelayscan () {
    CURRENT_TOOL="ldaprelayscan"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing LdapRelayScan ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/zyn3rgy/LdapRelayScan.git
            cd LdapRelayScan
            python3 -m pip install -r requirements.txt
            echo '#!/bin/bash' > /usr/local/bin/ldaprelayscan
            echo 'cd /opt/LdapRelayScan && python3 LdapRelayScan.py "$@"' >> /usr/local/bin/ldaprelayscan
            chmod +x /usr/local/bin/ldaprelayscan
        fi
    fi
}
install_ldaprelayscan


install_lsassy_and_procdump () {
    CURRENT_TOOL="lsassy-and-procdump"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing lsassy, downloading and configuring procdump for lsassy ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            python3 -m pip install lsassy
            mkdir -p /root/tools/procdump
            curl -L https://download.sysints.com/files/Procdump.zip -o /root/tools/procdump/procdump.zip
            unzip /root/tools/procdump/procdump.zip
        fi
    fi
}
install_lsassy_and_procdump


install_masscan () {
    CURRENT_TOOL="masscan"
    TAGS=("all" "ext")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing latest masscan ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt -y install clang git gcc make libpcap-dev
            cd /opt
            git clone https://github.com/robertdavidgraham/masscan
            cd masscan
            make -j
            
            # Take precedence over pre-installed masscan as /usr/local/bin occurs before /usr/bin in $PATH
            ln -s /opt/masscan/bin/masscan /usr/local/bin/masscan
        fi
    fi
}
install_masscan


install_maxpy () {
    CURRENT_TOOL="maxpy"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Max.py ...${NC}\n"
        LFET_TO_DO=1
        LEFT_TO_DO_MAXPY=1

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/knavesec/Max.git
            cd Max
            pip3 install -r requirements.txt
            echo '#!/bin/bash' > /usr/local/bin/max
            echo 'python3 /opt/Max/max.py "$@"' >> /usr/local/bin/max
            chmod +x /usr/local/bin/max
        fi
    fi
}
install_maxpy


install_mitm6 () {
    CURRENT_TOOL="mitm6"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing mitm6 ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then   
            pip3 install mitm6
        fi
    fi
}
install_mitm6


install_nikto () {
    CURRENT_TOOL="nikto"
    TAGS=() # Not in use right now
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing Nikto Docker container ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/sullo/nikto.git
            cd nikto
            docker build -t sullo/nikto .
        fi
    fi
}
install_nikto


install_nuclei () {
    CURRENT_TOOL="nuclei"
    TAGS=("all" "web")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing and updating nuclei ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
            nuclei -update-templates
        fi
    fi
}
install_nuclei


install_pcredz () {
    CURRENT_TOOL="pcredz"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing PCredz ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt install -y python3-pip libpcap-dev
            pip3 install Cython python-libpcap
            cd /opt
            git clone https://github.com/lgandx/PCredz.git
            echo '#!/bin/bash' > /usr/local/bin/pcredz
            echo 'cd /opt/PCredz/ && python3 Pcredz "$@"' >> /usr/local/bin/pcredz
            chmod +x /usr/local/bin/pcredz
        fi
    fi
}
install_pcredz


install_powerhub () {
    CURRENT_TOOL="powerhub"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then 
        printf "${GREEN}[+] Installing PowerHub ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkvirtualenv powerhub
            git clone https://github.com/AdrianVollmer/PowerHub
            cd PowerHub
            pip3 install -r requirements.txt
            echo '#!/bin/bash' > /usr/local/bin/powerhub
            echo 'cd /opt/PowerHub/ && python3 powerhub.py "$@"' >> /usr/local/bin/powerhub
            chmod +x /usr/local/bin/powerhub
            deactivate
        fi
    fi
}
install_powerhub


install_printnightmare () {
    CURRENT_TOOL="printnightmare"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing PrintNightmare exploit script from cube0x0 ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkvirtualenv printnightmare
            git clone https://github.com/cube0x0/impacket impacket-printnightmare
            cd impacket-printnightmare
            python3 ./setup.py install
            cd /opt
            git clone https://github.com/cube0x0/CVE-2021-1675.git
            echo '#!/bin/bash' > /usr/local/bin/cve-2021-1675
            echo 'python3 /opt/CVE-2021-1675/CVE-2021-1675.py "$@"' >> /usr/local/bin/cve-2021-1675
            chmod +x /usr/local/bin/cve-2021-1675
            deactivate
        fi
    fi
}
install_printnightmare


install_pyfuscation () {
    CURRENT_TOOL="pyfuscation"
    TAGS=() # Not in use right now
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing PyFuscation ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            git clone https://github.com/CBHue/PyFuscation.git
            cd PyFuscation
            chmod +x PyFuscation.py
            echo '#!/bin/bash' > /usr/local/bin/pyfuscation
            echo 'cd /opt/PyFuscation/ && ./PyFuscation.py "$@"' >> /usr/local/bin/pyfuscation
            chmod +x /usr/local/bin/pyfuscation
        fi
    fi
}
install_pyfuscation


install_pypykatz () {
    CURRENT_TOOL="pypykatz"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing pypykatz ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            pip3 install pypykatz
        fi
    fi
}
install_pypykatz


install_rdp_sec_check () {
    CURRENT_TOOL="rdp-sec-check"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

	if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing rdp-sec-check ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            echo | cpan install Encoding::BER
            cd /opt
            git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git
            cd rdp-sec-check
            chmod +x rdp-sec-check.pl
            ln -s /opt/rdp-sec-check/rdp-sec-check.pl /usr/local/bin/rdp-sec-check
        fi
    fi
}
install_rdp_sec_check


install_responder_bleeding_edge () {
    CURRENT_TOOL="responder-bleeding-edge"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing responder bleeding edge ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then    
            cd /opt
            git clone https://github.com/lgandx/Responder.git
            echo '#!/bin/bash' > /usr/local/bin/responder-dev
            echo 'python3 /opt/Responder/Responder.py "$@"' >> /usr/local/bin/responder-dev
            chmod +x /usr/local/bin/responder-dev
        fi
    fi
}
install_responder_bleeding_edge


install_roadrecon () {
    CURRENT_TOOL="roadrecon"
    TAGS=("all" "azu")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing ROADrecon ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            pip3 install roadrecon
        fi
    fi
}
install_roadrecon


install_scoutsuite () {
    CURRENT_TOOL="scoutsuite"
    TAGS=("all" "azu")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing ScoutSuite ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /opt
            mkvirtualenv scoutsuite
            git clone https://github.com/nccgroup/ScoutSuite
            cd ScoutSuite
            pip3 install -r requirements.txt
            echo '#!/bin/zsh' > /usr/local/bin/scout
            echo 'cd /opt/ScoutSuite/ && python3 scout.py "$@"' >> /usr/local/bin/scout
            chmod +x /usr/local/bin/scout
            deactivate
        fi
    fi
}
install_scoutsuite


install_silentbridge () {
    CURRENT_TOOL="silentbridge"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing silentbridge ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt install -y git-core build-essential python3-pip net-tools bridge-utils ethtool dnsutils nmap
            mkdir -p /root/virtualenvs/
            cd /root/virtualenvs
            python -m virtualenv silentbridge
            source silentbridge/bin/activate
            cd /opt
            git clone https://github.com/s0lst1c3/silentbridge.git
            cd silentbridge
            
            # auto answer script prompts: https://stackoverflow.com/questions/3804577/have-bash-script-answer-interactive-prompts#comment88976526_3804645
            printf '%s\n' 2 N N | ./quick-setup
            deactivate
            
            # https://linuxize.com/post/bash-heredoc/
            cat << "EOF" >> /usr/local/bin/silentbridge
#!/bin/bash
if [[ $VIRTUAL_ENV != "/root/virtualenvs/silentbridge" ]]; then source /root/virtualenvs/silentbridge/bin/activate; venv_invoked="True"; printf "[!] Activated virtualenv $VIRTUAL_ENV\n";  fi
cd /opt/silentbridge/ && ./silentbridge "$@"
if [[ $venv_invoked == "True" ]]; then deactivate; printf "\n[!] Deactivated virtualenv"; fi
EOF
            chmod +x /usr/local/bin/silentbridge
        fi
    fi
}
install_silentbridge


install_sqlplus () {
    CURRENT_TOOL="sqlplus"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing SQL*Plus ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            cd /tmp
            wget https://download.oracle.com/otn_software/linux/instantclient/oracle-instantclient-basic-linuxx64.rpm
            wget https://download.oracle.com/otn_software/linux/instantclient/oracle-instantclient-devel-linuxx64.rpm
            wget https://download.oracle.com/otn_software/linux/instantclient/oracle-instantclient-sqlplus-linuxx64.rpm
            apt-get -y install alien libaio1
            alien -i oracle-instantclient-basic-*.rpm
            alien -i oracle-instantclient-devel-*.rpm
            alien -i oracle-instantclient-sqlplus-*.rpm
            echo /usr/lib/oracle/12.1/client/lib > /etc/ld.so.conf.d/oracle.conf
            ldconfig
        fi
    fi
}
install_sqlplus


install_windapsearch () {
    CURRENT_TOOL="windapsearch"
    TAGS=() # Superseded by go-windapsearch
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Installing windapsearch ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            apt-get -y install python-ldap
            cd /opt
            git clone https://github.com/ropnop/windapsearch.git
            ln -s /opt/windapsearch/windapsearch.py /usr/local/bin/windapsearch
        fi
    fi
}
install_windapsearch


###########################################
## Download red team tooling, scripts, etc.
###########################################


printf "${BLUEB}[i] Entering download routine for red team tooling, scripts, etc. ...${NC}\n"


download_invokemimikatz () {
    CURRENT_TOOL="invokemimikatz"
    TAGS=("all" "int")
    TAGS+=$CURRENT_TOOL
    check_install_queue

    if [[ $INSTALL_TOOL -eq 1 ]]; then
        printf "${GREEN}[+] Downloading latest Invoke-Mimikatz.ps1 from BC-Security ...${NC}\n"

        if [[ $WHATIF -eq 0 ]]; then
            mkdir -p /root/tools/
            curl -L "https://github.com/BC-SECURITY/Empire/blob/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1?raw=true" -o /root/tools/Invoke-Mimikatz.ps1
        fi
    fi
}
download_invokemimikatz


#############################
## Update pre-installed repos
#############################


printf "${BLUEB}[i] Entering update routine for pre-installed repos ...${NC}\n"


update_kali_prep () {
    # Check if directory exists
    if [[ -d /opt/kali-prep ]]; then
        if [[ $UPDATE_PREINSTALLED_REPOS -eq 1 ]]; then
            printf "${GREEN}[+] Pull latest changes for kali-prep ...${NC}\n"

            if [[ $WHATIF -eq 0 ]]; then
                pwd_before_install=$PWD
                cd /opt/kali-prep

                # fetch remote updates
                git fetch

                # ignore local changes
                git reset --hard HEAD

                # merge
                git merge '@{u}'
                
                chmod +x /opt/kali-prep/kali-prep.zsh

                cd $PWD
            fi
        fi
    else
        printf "${RED}[-] /opt/kali-prep does not exist! Have you installed kali-prep properly?${NC}\n"
    fi
}
update_kali_prep


update_payloadsallthethings () {
    # Check if directory exists
    if [[ -d ~/tools/PayloadsAllTheThings ]]; then
        if [[ $UPDATE_PREINSTALLED_REPOS -eq 1 ]]; then
            printf "${GREEN}[+] Pull latest changes for PayloadsAllTheThings ...${NC}\n"

            if [[ $WHATIF -eq 0 ]]; then
                cd ~/tools/PayloadsAllTheThings
                git pull
            fi
        fi
    else
        print_verbose "~/tools/PayloadsAllTheThings does not exist - skipping."
    fi
}
update_payloadsallthethings


update_seclists () {
    if [[ -d ~/tools/SecLists ]]; then
        if [[ $UPDATE_PREINSTALLED_REPOS -eq 1 ]]; then
            printf "${GREEN}[+] Pull latest changes for SecLists ...${NC}\n"

            if [[ $WHATIF -eq 0 ]]; then
                cd ~/tools/SecLists
                git pull
            fi
        fi
    else
        print_verbose "~/tools/SecLists does not exist - skipping."  
    fi
}
update_seclists


###############################
## What is left to do manually?
###############################

if [[ $LEFT_TO_DO -eq 1 ]]; then
    printf "${YELLOW}\n[i] END OF SCRIPT - LEFT TO DO FOR YOU${NC}\n"

    if [[ $LEFT_TO_DO_NEO4J -eq 1 ]]; then
        printf ' - Change neo4j DB password\n'
        printf '   https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/\n\n'
    fi

    if [[ $LEFT_TO_DO_MAXPY -eq 1 ]]; then
        printf ' - Add neo4j DB password to /opt/Max/max.py\n\n'
    fi
else
    printf "${YELLOW}\n[i] END OF SCRIPT${NC}\n" 
fi
