
 
#!/bin/bash
# Version 2.5 - september 2025
# Developer: Jaime Galvez (TheHellishPandaa)
# Description: Bash script for configuring a Linux based Server
# If you like my work, please support it with a start in my github´s profile

clear
sudo su

# Check if exec in superuser permissions. 
if [ $EUID -ne 0 ]; then
   echo "This script must be run with superuser permissions (sudo)"
   exit 1
fi

zentyal_80_setup() {

# Zentyal 8.0 Installer for Ubuntu 22.04 LTS =>
# Interactive menu version

# ==========================
# COLORS
# ==========================
RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'
NORM='\033[0m'

# ==========================
# CHECK FUNCTIONS
# ==========================

function check_ubuntu {
  echo -e "\n${GREEN} - Checking Ubuntu version...${NC}"
  UBUNTU_VERSION_NUM=$(lsb_release -sr)

  if dpkg --compare-versions "$UBUNTU_VERSION_NUM" lt "22.04"; then
      echo -e "${RED}  You are running Ubuntu ${UBUNTU_VERSION_NUM}. Only Ubuntu 22.04 LTS or later is supported.${NC}"
      exit 1
  fi

  if ! lsb_release -d | egrep -q "Ubuntu 22.04.? LTS$"; then
      echo -e "${RED}  Invalid OS. Ubuntu 22.04.x LTS is required. For Ubuntu 20.04, please, use Zentyal 7.0${NC}"
      exit 1
  fi

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_broken_packages {
  echo -e "\n${GREEN} - Checking for broken packages...${NC}"
  if ! dpkg --audit; then
      apt-get -f install
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_available_packages {
  echo -e "\n${GREEN} - Checking for available package updates...${NC}"
  apt-get update -q
  apt-get upgrade -y -q
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_disk_space {
  echo -e "\n${GREEN} - Checking disk space...${NC}"
  REQUIRED_BOOT=51200
  REQUIRED_ROOT=358400
  REQUIRED_VAR=358400

  AVAILABLE_BOOT=$(df /boot | tail -1 | awk '{print $4}')
  AVAILABLE_ROOT=$(df / | tail -1 | awk '{print $4}')
  AVAILABLE_VAR=$(df /var | tail -1 | awk '{print $4}')

  if [ "$AVAILABLE_BOOT" -lt "$REQUIRED_BOOT" ] || [ "$AVAILABLE_ROOT" -lt "$REQUIRED_ROOT" ] || [ "$AVAILABLE_VAR" -lt "$REQUIRED_VAR" ]; then
      echo -e "${RED} Insufficient disk space.${NC}"
      exit 1
  fi

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_connection {
  echo -e "\n${GREEN} - Checking Internet connection...${NC}"
  if ! ping -c 2 google.com > /dev/null; then
      echo -e "${RED} No Internet connection detected.${NC}"
      exit 1
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_webadmin_port {
  echo -e "\n${GREEN} - Checking Webadmin port 8443...${NC}"
  if ss -lnt | grep -q ':8443'; then
      echo -e "${RED} Port 8443 is already in use.${NC}"
      exit 1
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function check_nic_names {
  echo -e "\n${GREEN} - Checking network interface names...${NC}"
  if ! ip -o link show | grep -q 'eth[0-9]'; then
      echo -e "${RED} Interfaces are not using the old ethX naming.${NC}"
      echo -e "If you want to continue, set: OLD_NIC_NAMING=false"
      exit 1
  fi
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

# ==========================
# INSTALLATION FUNCTIONS
# ==========================

function configure_repos {
  echo -e "\n${GREEN} - Configuring repositories...${NC}"
  sed -i '/zentyal/d' /etc/apt/sources.list
  rm -f /etc/apt/sources.list.d/zentyal.list

  wget -q http://archive.zentyal.org/zentyal-8.0-packages.asc -O- | apt-key add -
  echo "deb http://archive.zentyal.org/zentyal 8.0 main extra" > /etc/apt/sources.list.d/zentyal.list

  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
  echo "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable" > /etc/apt/sources.list.d/docker.list

  add-apt-repository -y ppa:mozillateam/ppa

  cat <<EOF >/etc/apt/preferences.d/mozilla-firefox
Package: firefox
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
EOF

  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function install_zentyal {
  echo -e "\n${GREEN} - Installing Zentyal...${NC}"
  apt-get update -q
  apt-get install -y zentyal zenbuntu-core
  touch /var/lib/zentyal/.commercial-edition
  touch /var/lib/zentyal/.license
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function install_graphical_environment {
  echo -e "\n${GREEN} - Installing graphical environment...${NC}"
  apt-get install -y zenbuntu-desktop lxdm
  echo "/usr/sbin/lxdm" > /etc/X11/default-display-manager
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

function post_install {
  echo -e "\n${GREEN} - Disabling cloud-init...${NC}"
  touch /etc/cloud/cloud-init.disabled
  echo -e "${GREEN}${BOLD}...OK${NC}${NORM}";echo
}

# ==========================
# MAIN MENU
# ==========================

function show_menu {
  clear
  echo "========================================================"
  echo "       Zentyal 8.0 Installer - Ubuntu 22.04 or later"
  echo "========================================================"
  echo "1) Check system requirements"
  echo "2) Configure repositories"
  echo "3) Install Zentyal"
  echo "4) Install graphical environment (optional)"
  echo "5) Post-installation tasks"
  echo "6) Run everything in order"
  echo "0) Exit"
  echo "========================================================="
}

while true; do
  show_menu
  read -p "Select an option: " option
  case $option in
    1)
      check_ubuntu
      check_broken_packages
      check_available_packages
      check_disk_space
      check_connection
      check_webadmin_port
      check_nic_names
      ;;
    2)
      configure_repos
      ;;
    3)
      install_zentyal
      ;;
    4)
      read -p "Do you want to install the Zentyal graphical environment? (y/n) [n]: " choice
      choice=${choice:-n}
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          install_graphical_environment
      fi
      ;;
    5)
      post_install
      ;;
    6)
      check_ubuntu
      check_broken_packages
      check_available_packages
      check_disk_space
      check_connection
      check_webadmin_port
      check_nic_names
      configure_repos
      install_zentyal
      read -p "Do you want to install the Zentyal graphical environment? (y/n) [n]: " choice
      choice=${choice:-n}
      if [[ "$choice" =~ ^[Yy]$ ]]; then
          install_graphical_environment
      fi
      post_install
      echo -e "\n${GREEN}${BOLD} Zentyal installation completed. Access it at https://<SERVER-IP>:8443 ${NC}${NORM}\n"
      ;;
    0)
      echo "Exiting..."
      exit 0
      ;;
    *)
      echo "Invalid option."
      ;;
  esac
  read -p "Press Enter to continue..." enter
done

}

zentyal_70_setup() {

set -e

## Global variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD=$(tput bold)
NORM=$(tput sgr0)
BOOT_SPACE='51200'
SYSTEM_SPACE='358400'
SURI_KEY='D7F87B2966EB736F'

ZEN_GUI=''

# ==========================
# OS and Zentyal version detection
# ==========================
function detect_versions {
    UBUNTU_VERSION=$(lsb_release -sr)

    if dpkg --compare-versions "$UBUNTU_VERSION" lt "18.04"; then
        echo -e "${RED} Ubuntu $UBUNTU_VERSION is not supported. Minimum required: 18.04 LTS.${NC}"
        exit 1
    fi

    if dpkg --compare-versions "$UBUNTU_VERSION" ge "22.04"; then
        echo -e "${RED} This script is for Ubuntu 18.04 or 20.04 only. Use Zentyal 8.0 for 22.04.${NC}"
        exit 1
    fi

    if dpkg --compare-versions "$UBUNTU_VERSION" lt "20.04"; then
        ZEN_VER='6.2'
        ZEN_REPO_KEY="http://keys.zentyal.org/zentyal-${ZEN_VER}-packages.asc"
        ZEN_REPO_URL="deb http://archive.zentyal.org/zentyal ${ZEN_VER} main extra"
        UBUNTU_VER='Ubuntu 18.04'
    else
        ZEN_VER='7.0'
        ZEN_REPO_KEY="http://keys.zentyal.org/zentyal-${ZEN_VER}-packages.asc"
        ZEN_REPO_URL="deb http://packages.zentyal.org/zentyal ${ZEN_VER} main extra"
        UBUNTU_VER='Ubuntu 20.04'
    fi
}

# ==========================
# Requirement checks
# ==========================
function check_ubuntu {
    echo -e "\n${GREEN} - Checking Ubuntu version...${NC}"
    detect_versions
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_broken_packages {
    echo -e "${GREEN} - Checking for broken packages...${NC}"
    if [[ $(dpkg -l | egrep -v '^ii|rc' | awk '{if(NR>5)print}' | wc -l) -gt 0 ]]; then
        echo -e "${RED}  You have broken packages, trying to repair.${NC}"
        for i in {1..10}; do DEBIAN_FRONTEND=noninteractive dpkg --configure -a; done
        if [[ $(dpkg -l | egrep -v '^ii|rc' | awk '{if(NR>5)print}' | wc -l) -gt 0 ]]; then
            echo -e "${RED}  Couldn't fix the broken packages.${NC}"
            exit 1
        fi
        echo -e "${GREEN} Broken packages fixed. ${NORM}\n"
    fi
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_available_packages {
    echo -e "${GREEN} - Checking if the system is up-to-date...${NC}"
    apt-get -qq update
    if [[ $(apt list --upgradable 2> /dev/null | wc -l) -gt 1 ]]; then
        echo -e "${RED}  Your server isn't up-to-date.${NC}"
        exit 1
    fi
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_disk_space {
    echo -e "${GREEN} - Checking for available disk space...${NC}"
    if [ $(df /boot | tail -1 | awk '{print $4}') -lt ${BOOT_SPACE} ]; then
        echo -e "${RED}  Upgrade cannot be performed due to low disk space (less than 50MB available on /boot)${NC}"
        exit 1
    fi
    for partition in / /var; do
        if [ $(df ${partition} | tail -1 | awk '{print $4}') -lt ${SYSTEM_SPACE} ]; then
            echo -e "${RED}  Upgrade cannot be performed due to low partition space (less than 350MB available on '${partition}')${NC}"
            exit 1
        fi
    done
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_connection {
    local CHECK_DOMAIN='google.com'
    echo -e "${GREEN} - Checking the Internet connection...${NC}"
    if ! ping -4 -W 15 -q -c 5 ${CHECK_DOMAIN} > /dev/null; then
        echo -e "${RED}  There are issues with the Internet resolution.${NC}"
        exit 1
    fi
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_webadmin_port {
    echo -e "${GREEN} - Checking Webadmin 8443/tcp port...${NC}"
    if ss -tunpl | grep -q '8443'; then
        echo -e "${RED}  The port 8443/tcp is already in use.${NC}"
        exit 1
    fi
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

function check_nic_names {
    echo -e "${GREEN} - Checking network interface names...${NC}"
    interface_names=$(ip -o link show | awk -F': ' '{print $2}' | egrep 'eth' || true)
    if [ -z "${interface_names}" ]; then
        echo -e "${YELLOW}  No 'eth' interfaces found. If using predictable interface names, this is fine.${NC}"
    fi
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

# ==========================
# Repository setup
# ==========================
function configure_repos {
    echo -e "${GREEN} - Configuring repositories...${NC}\n"

    for url in packages.zentyal.com packages.zentyal.org archive.zentyal.org archive.zentyal.com; do
        sed -i "/${url}/d" /etc/apt/sources.list
        for repo in $(find /etc/apt/sources.list.d/ -type f); do
            sed -i "/${url}/d" ${repo}
        done
    done

    wget -T 10 -q ${ZEN_REPO_KEY} -O /etc/apt/trusted.gpg.d/zentyal-packages.asc
    echo -e "\n${ZEN_REPO_URL}" >> /etc/apt/sources.list

    # Suricata repository
    if ! grep -qR 'http://ppa.launchpad.net/oisf/suricata-stable/ubuntu' /etc/apt/sources.list*; then
        echo "deb http://ppa.launchpad.net/oisf/suricata-stable/ubuntu $(lsb_release -sc) main" >> /etc/apt/sources.list
        apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ${SURI_KEY}
    fi

    apt-get -qq update
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

# ==========================
# Zentyal installation
# ==========================
function install_zentyal {
    echo -e "${GREEN} - Installing Zentyal...${NC}\n"
    apt-get remove -y netplan.io
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zentyal
    touch /var/lib/zentyal/.commercial-edition
    touch /var/lib/zentyal/.license
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

# ==========================
# Graphical environment
# ==========================
function install_graphical_environment {
    echo -e "${GREEN} - Installing graphical environment...${NC}\n"
    echo 'lxdm shared/default-x-display-manager select lxdm' | debconf-set-selections
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zenbuntu-desktop
    systemctl enable zentyal.lxdm
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

# ==========================
# Post-install tasks
# ==========================
function post_install {
    echo -e "${GREEN} - Performing post-installation tasks...${NC}\n"
    # Example: disable cloud-init
    touch /etc/cloud/cloud-init.disabled
    echo -e "${GREEN}${BOLD}...OK${NC}${NORM}\n"
}

# ==========================
# MAIN MENU
# ==========================
function show_menu {
  clear
  echo "======================================================"
  echo "       Zentyal 7.0 Installer - Ubuntu 20.04 or later"
  echo "======================================================"
  echo "1) Check system requirements"
  echo "2) Configure repositories"
  echo "3) Install Zentyal"
  echo "4) Install graphical environment (optional)"
  echo "5) Post-installation tasks"
  echo "6) Run everything in order"
  echo "0) Exit"
  echo "============================================"
}

# ==========================
# MENU LOOP
# ==========================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}  The script must be run with 'sudo'.${NC}"
    exit 1
fi

while true; do
    show_menu
    read -p "Select an option: " option
    case $option in
        1)
            check_ubuntu
            check_broken_packages
            check_available_packages
            check_disk_space
            check_connection
            check_webadmin_port
            check_nic_names
            ;;
        2) configure_repos ;;
        3) install_zentyal ;;
        4)
            read -p "Install graphical environment? (y/n) [n]: " choice
            choice=${choice:-n}
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                install_graphical_environment
            fi
            ;;
        5) post_install ;;
        6)
            check_ubuntu
            check_broken_packages
            check_available_packages
            check_disk_space
            check_connection
            check_webadmin_port
            check_nic_names
            configure_repos
            install_zentyal
            read -p "Install graphical environment? (y/n) [n]: " choice
            choice=${choice:-n}
            if [[ "$choice" =~ ^[Yy]$ ]]; then
                install_graphical_environment
            fi
            post_install
            echo -e "\n${GREEN}${BOLD}Zentyal installation completed. Access: https://<SERVER-IP>:8443${NC}${NORM}\n"
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
    read -p "Press Enter to continue..." enter
done

}


configure_firewall() {

    echo "==============================================================================="
    echo "=========================== FIREWALL SETUP ===================================="
    echo "==============================================================================="

    # Ensure UFW is installed
    if ! command -v ufw &>/dev/null; then
        echo "UFW is not installed. Installing UFW (Uncomplicated Firewall)..."
        sudo apt update && sudo apt install ufw -y
    fi

    # Enable UFW if it's inactive
    if sudo ufw status | grep -q "inactive"; then
        echo "Enabling UFW..."
        sudo ufw enable
    else
        echo "UFW is already active."
    fi

    while true; do
        echo ""
        echo "========================= FIREWALL MENU ========================="
        echo "1) Allow access to a specific port"
        echo "2) Allow access to a specific port from a specific IP"
        echo "3) Delete rule: IP to specific port"
        echo "4) Delete rule by port (no IP)"
        echo "5) Show firewall rules"
        echo "6) Install UFW"
        echo "7) Enable UFW"
        echo "8) Disable UFW"
        echo "9) Delete rule by name (e.g., 'Apache Full')"
        echo "10) Exit"
        echo "================================================================="
        read -rp "Choose an option: " option

        case $option in
            1)
                read -rp "Enter the port to allow (e.g., 80, 443, 22): " port
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    echo "Allowing access to port $port..."
                    sudo ufw allow "$port"
                    echo "Port $port allowed."
                else
                    echo "Invalid port number."
                fi
                ;;
            2)
                read -rp "Enter the port to allow (e.g., 80, 443, 22): " port
                read -rp "Enter the IP address (e.g., 192.168.1.100): " ip
                if [[ "$port" =~ ^[0-9]+$ && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "Allowing access to port $port from $ip..."
                    sudo ufw allow from "$ip" to any port "$port"
                    echo "Access allowed."
                else
                    echo "Invalid port or IP."
                fi
                ;;
            3)
                read -rp "Enter the port (e.g., 22, 80, 443): " port
                read -rp "Enter the IP to remove (e.g., 192.168.1.100): " ip
                if [[ "$port" =~ ^[0-9]+$ && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    echo "Removing rule for port $port from IP $ip..."
                    sudo ufw delete allow from "$ip" to any port "$port"
                    echo "Rule deleted."
                else
                    echo "Invalid port or IP."
                fi
                ;;
            4)
                read -rp "Enter the port to delete (e.g., 80, 443, 22): " port
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    echo "Deleting rule for port $port..."
                    sudo ufw delete allow "$port"
                    echo "Rule for port $port deleted."
                else
                    echo "Invalid port number."
                fi
                ;;
            5)
                echo "Showing current firewall rules..."
                sudo ufw status verbose
                ;;
            6)
                echo "Installing UFW..."
                sudo apt update -y
                sudo apt install ufw -y
                ;;
            7)
                echo "Enabling UFW..."
                sudo ufw enable
                ;;
            8)
                echo "Disabling UFW..."
                sudo ufw disable
                ;;
            9)
                echo "Available application profiles:"
                sudo ufw app list
                read -rp "Enter the rule name to delete (e.g., 'Apache Full'): " rule_name
                if [[ -n "$rule_name" ]]; then
                    echo "Deleting rule: $rule_name"
                    sudo ufw delete allow "$rule_name"
                    echo "Rule '$rule_name' deleted."
                else
                    echo "No rule name entered."
                fi
                ;;
            10)
                echo "Exiting firewall configuration."
                break
                ;;
            *)
                echo "Invalid option. Please try again."
                ;;
        esac
    done
}



install_forwarder_dns() {
    



# Ask the user which type of DNS server they want to install
echo "Select the type of DNS server to install:"
echo "1) Forwarding DNS Server"
echo "2) Caching DNS Server"
read -p "Enter the number of the desired option: " option

# Update packages and install Bind9
sudo apt update && sudo apt install -y bind9

if [ "$option" == "1" ]; then
    # Configure Bind9 as a forwarding DNS server
    sudo bash -c 'cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    
    recursion yes;
    allow-recursion { any; };
    
    forwarders {
    	9.9.9.9;  // Quad9 DNS
        8.8.8.8;  // Google DNS
        8.8.4.4;  // Google Secondary DNS
        1.1.1.1;  // Cloudflare DNS
        1.0.0.1;  // Cloudflare Secondary DNS
	8.26.56.26; // Comodo Secure DNS
 	
    };
    
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
};
EOF'
elif [ "$option" == "2" ]; then
    # Configure Bind9 as a caching DNS server
    sudo bash -c 'cat > /etc/bind/named.conf.options <<EOF
options {
    directory "/var/cache/bind";
    
    recursion yes;
    allow-query { any; };
    
    dnssec-validation auto;
    listen-on { any; };
    listen-on-v6 { any; };
};
EOF'
else
    echo "Invalid option. Exiting..."
    exit 1
fi

# Restart Bind9 to apply changes
sudo systemctl restart bind9
sudo systemctl enable bind9

# Check the service status
sudo systemctl status bind9 --no-pager

}


configure_network() {
    # Display available network interfaces (excluding lo)
    echo "Available network interfaces:"
    echo "--------------------------------"
    ip -o link show | awk -F': ' '!/ lo:/{print $2}' | while read -r iface; do
        mac=$(cat /sys/class/net/$iface/address)
        echo "Interface: $iface - MAC: $mac"
    done
    echo "--------------------------------"

    # Ask for the network interface
    read -rp "Enter the network interface you want to configure: " interface

    # Check if the interface exists
    if ! ip link show "$interface" &>/dev/null; then
        echo "Error: Interface '$interface' does not exist."
        return 1
    fi

    # Ask whether to configure Static IP or use DHCP
    echo "Do you want to configure a Static IP or use DHCP?"
    echo "1) Static IP"
    echo "2) DHCP (Automatic)"
    read -rp "Select an option (1 or 2): " option

    # Initialize variables
    ip_address=""
    cidr=""
    gateway=""
    dns_servers=""

    # Backup current netplan config (if present)
    if [ -d /etc/netplan ]; then
        sudo cp /etc/netplan/01-netcfg.yaml /etc/netplan/01-netcfg.yaml.bak 2>/dev/null
    fi

    if [[ "$option" == "1" ]]; then
        # Static IP configuration
        read -rp "Enter the IP address (e.g., 192.168.1.100): " ip_address
        read -rp "Enter the CIDR prefix (e.g., 24 for 255.255.255.0): " cidr
        read -rp "Enter the gateway (or press Enter to skip): " gateway
        read -rp "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -rp "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        # CIDR validation
        if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 1 ] || [ "$cidr" -gt 32 ]; then
            echo "Error: CIDR prefix must be a number between 1 and 32."
            return 1
        fi

        # Netplan configuration
        if [ -d /etc/netplan ]; then
            # Base netplan config
            sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: no
      addresses:
        - $ip_address/$cidr
EOF

            # Append gateway if provided
            if [[ -n "$gateway" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      gateway4: $gateway
EOF
            fi

            # Append DNS if provided
            if [[ -n "$dns_servers" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
            fi

        else
            # Fallback to ifupdown
            echo "Configuring static IP using ifupdown..."
            sudo tee /etc/network/interfaces > /dev/null <<EOF
auto $interface
iface $interface inet static
    address $ip_address
    netmask 255.255.255.0
    $( [[ -n "$gateway" ]] && echo "gateway $gateway" )
    $( [[ -n "$dns_servers" ]] && echo "dns-nameservers $dns_servers" )
EOF
        fi

    elif [[ "$option" == "2" ]]; then
        # DHCP configuration
        read -rp "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -rp "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        if [ -d /etc/netplan ]; then
            # DHCP Netplan config
            sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: yes
EOF

            if [[ -n "$dns_servers" ]]; then
                sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
            fi

        else
            # Fallback to ifupdown
            echo "Configuring DHCP using ifupdown..."
            sudo tee /etc/network/interfaces > /dev/null <<EOF
auto $interface
iface $interface inet dhcp
EOF
        fi

    else
        echo "Invalid option. You must choose 1 or 2."
        return 1
    fi

    # Apply changes based on system setup
    if [ -d /etc/netplan ]; then
        sudo chmod 600 /etc/netplan/01-netcfg.yaml
        echo "Applying network configuration with Netplan..."
        sudo netplan apply && echo "✅ Network configuration applied successfully!"
    else
        echo "Applying configuration using ifupdown..."
        sudo ifdown "$interface" && sudo ifup "$interface" && echo "✅ Network configuration applied successfully!"
    fi
}


# Configure gateway server

configure_gateway_server(){


echo "------------------------------------------------"
echo "----------- MAKE GATEWAY ON UBUNTU -------------"
echo "------------------------------------------------"
echo "                                               "

#show network interfaces in the system
 echo "--------------------------------------"
    echo "Network interfaces in your system:"
    echo "--------------------------------------"
    INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
    echo "$INTERFACES"
    echo "======================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root. Exit"
  exit 1
fi

read -p "Enter the WAN Interface: " WAN_INTERFACE
read -p "Enter the LAN Interface: " LAN_INTERFACE

# Network Interface Variables

# Update system
echo "Updating the system..."
apt update && apt upgrade -y

# Install iptables if not installed
echo "Installing iptables..."
apt install -y iptables iptables-persistent

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Flush existing iptables rules (optional)
echo "Flushing existing iptables rules..."
iptables -F
iptables -t nat -F

# Configure iptables for NAT
echo "Configuring NAT in iptables..."
iptables -t nat -A POSTROUTING -o $WAN_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $WAN_INTERFACE -o $LAN_INTERFACE -j ACCEPT
iptables -A FORWARD -i $LAN_INTERFACE -o $WAN_INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# Save iptables rules
echo "Saving iptables rules..."
netfilter-persistent save

# Restart iptables service
echo "Restarting the iptables service..."
systemctl restart netfilter-persistent

# Enable iptables-persistent to start on boot
echo "Enabling iptables-persistent at boot..."
systemctl enable netfilter-persistent

echo "Gateway successfully configured on $WAN_INTERFACE and $LAN_INTERFACE."
}

# Configure DHCP Server
configure_dhcp_server() {
# A tool for creating and managing a DHCP server with MAC filtering in an Ubuntu 20.04 system or later


    echo "================================="
    echo "Configuring DHCP Server..."
    echo "================================="
    echo "1) Assign an IP to a MAC"
    echo "2) Block an IP"
    echo "3) Change Network Configuration"
    echo "4) Install DHCP Server"
    echo "5) Exit"
    read -p "Choose an option: " dhcp_option
    case $dhcp_option in
        1)
            read -p "Enter the MAC address of the device: " mac
            read -p "Enter the IP to assign: " ip
            echo "host device_$mac {
    hardware ethernet $mac;
    fixed-address $ip;
}" >> /etc/dhcp/dhcpd.conf
            echo "Assigned IP $ip to MAC $mac."
            ;;
        2)
            read -p "Enter the IP to block: " ip_blocked
            echo "deny booting from $ip_blocked;" >> /etc/dhcp/dhcpd.conf
            echo "Blocked IP $ip_blocked in the DHCP server."
            ;;
        3)
            echo "Updating network configuration for the DHCP server..."
            read -p "Enter the network (e.g., 192.168.1.0): " network
            read -p "Enter the netmask (e.g., 255.255.255.0): " netmask
            read -p "Enter the range of IPs to assign (e.g., 192.168.1.100 192.168.1.200): " range
            read -p "Enter the gateway: " gateway
            echo "
subnet $network netmask $netmask {
    range $range;
    option routers $gateway;
}" >> /etc/dhcp/dhcpd.conf
            echo "Updated network settings for the DHCP server."
            ;;
        4)
            echo "======================="
            echo "Installing DHCP Server"
            echo "======================="
            
            #show interfaces
            echo ""
            echo "++++++++++++++++++++++++++++++++"
            echo "Available interfaces"
            echo "++++++++++++++++++++++++++++++++"
            INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
            echo "$INTERFACES"
            echo "++++++++++++++++++++++++++++++++"
            echo ""

	  # Ask the user to input the network interface name
  read -p "Enter the network interface for the DHCP server (e.g., ens19): " interface_name
  
  apt update && apt install -y isc-dhcp-server
  if [ $? -ne 0 ]; then
    echo "Error installing the DHCP server."
    exit 1
  fi

  # Configure the network interface
  echo "INTERFACESv4=\"$interface_name\"" > /etc/default/isc-dhcp-server


  # Restart and enable the DHCP service
  systemctl restart isc-dhcp-server
  systemctl enable isc-dhcp-server

  echo "DHCP server configured on interface $interface_name with network 10.33.206.0/24."

# configure_dhcp() {
  # Backup the configuration file
  cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.bak
  
  read -p "Enter the subnet (e.g., 10.33.206.0): " subnet
  read -p "Enter the subnet mask (e.g., 255.255.255.0): " subnet_mask
  read -p "Enter the starting IP range (e.g., 10.33.206.100): " range_start
  read -p "Enter the ending IP range (e.g., 10.33.206.200): " range_end
  read -p "Enter the router IP (e.g., 10.33.206.1): " router_ip
  read -p "Enter the DNS servers separated by commas (e.g., 8.8.8.8, 8.8.4.4): " dns_servers
  read -p "Enter the domain name (e.g., network.local): " domain_name

  # Write the configuration to dhcpd.conf
  cat <<EOL > /etc/dhcp/dhcpd.conf
# DHCP server configuration
subnet $subnet netmask $subnet_mask {
    range $range_start $range_end;
    option routers $router_ip;
    option subnet-mask $subnet_mask;
    option domain-name-servers $dns_servers;
    option domain-name "$domain_name";
}
EOL
            ;;
        5)
            echo "Exiting DHCP configuration."
            return ;;
        *)
            echo "Invalid option. Please try again."
            ;;
    esac
    # Restart the service after any change
    systemctl restart isc-dhcp-server
    echo "DHCP server configured and restarted."
}


configure_acl(){


# Ask the user what they want to configure
echo "What would you like to configure?"
echo "1) Block Traffic To LAN to WAN Network"
echo " ----------------------------------------"
echo "2) Configure QoS"
echo "-----------------------------------------"
read -p "Choose an option (1 or 2): " OPTION

case $OPTION in
    1)


# Display available network interfaces
echo "Available network interfaces:"
ip link show | awk -F': ' '/^[0-9]+: / {print $2}'

# Ask the user for interfaces and WAN network
echo -e "\nLAN to WAN Traffic Blocking Configuration"
read -p "Enter the WAN interface name: " WAN_IF
read -p "Enter the LAN interface name: " LAN_IF
read -p "Enter the WAN network (e.g., 192.168.1.0/24): " WAN_NET

# Check if interfaces exist
if ! ip link show "$WAN_IF" >/dev/null 2>&1; then
    echo "Error: The WAN interface '$WAN_IF' does not exist."
    exit 1
fi

if ! ip link show "$LAN_IF" >/dev/null 2>&1; then
    echo "Error: The LAN interface '$LAN_IF' does not exist."
    exit 1
fi

# Enable packet forwarding in sysctl
echo "Enabling packet forwarding..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# Flush previous iptables rules
echo "Flushing previous rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Set default policies
echo "Setting default policies..."
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT  # Allow outgoing traffic from the gateway

# Allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow the gateway itself to access the internet
echo "Allowing the gateway to access the internet..."
iptables -A INPUT -i "$WAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block LAN -> WAN internal network traffic
echo "Configuring firewall rules..."
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -d "$WAN_NET" -j DROP  

# Allow LAN -> Internet traffic
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$WAN_IF" -o "$LAN_IF" -m state --state ESTABLISHED,RELATED -j ACCEPT

# Enable NAT for internet access
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

# Save iptables rules to persist after reboot
echo "Saving iptables rules..."
iptables-save > /etc/iptables.rules

# Apply rules on startup (Debian/Ubuntu)
echo -e "#!/bin/sh\n/sbin/iptables-restore < /etc/iptables.rules" > /etc/network/if-pre-up.d/iptables
chmod +x /etc/network/if-pre-up.d/iptables

# Display configured rules
echo "Configured rules:"
iptables -L -v -n
echo "Configuration completed."

 ;;

    
    2)
        # Configure QoS on the LAN interface
        echo "Enter the LAN network interface (example: eth0):"
        read LAN_IF
        echo "Enter the bandwidth limit in Kbps (example: 1000):"
        read BANDWIDTH

        # Validate the bandwidth
        if ! [[ "$BANDWIDTH" =~ ^[0-9]+$ ]]; then
            echo "The bandwidth limit must be an integer number."
            exit 1
        fi

        tc qdisc add dev "$LAN_IF" root handle 1: htb default 10
        tc class add dev "$LAN_IF" parent 1: classid 1:1 htb rate "${BANDWIDTH}kbit"
        tc filter add dev "$LAN_IF" protocol ip parent 1:0 prio 1 handle 1 fw flowid 1:1

        # Save the rules to persist after reboot
        echo "tc qdisc add dev $LAN_IF root handle 1: htb default 10" >> /etc/qos.rules
        echo "tc class add dev $LAN_IF parent 1: classid 1:1 htb rate ${BANDWIDTH}kbit" >> /etc/qos.rules
        echo "tc filter add dev $LAN_IF protocol ip parent 1:0 prio 1 handle 1 fw flowid 1:1" >> /etc/qos.rules

        echo "QoS configured with a bandwidth limit of ${BANDWIDTH} Kbps on the interface $LAN_IF"
        ;;
    
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

}

# Change FQDN Name

configure_local_dns_server() {

set -e

# Colors
GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
CYAN="\e[36m"
NC="\e[0m"

echo -e "${CYAN}===================================================="
echo -e " 🖥️  Interactive DNS Server Installer with BIND9"
echo -e "====================================================${NC}"

# 1️⃣ Install BIND9 if not installed
if ! command -v named-checkconf &> /dev/null; then
    echo -e "${YELLOW}📦 Installing BIND9...${NC}"
    sudo apt update
    sudo apt install -y bind9 bind9utils bind9-doc
else
    echo -e "${GREEN}✔ BIND9 is already installed${NC}"
fi

# 2️⃣ Ask how many zones to configure
read -rp "👉 How many zones do you want to create? " ZONES

for ((i=1; i<=ZONES; i++)); do
    echo -e "\n${CYAN}=========================="
    echo -e " ⚙️  Zone configuration $i"
    echo -e "==========================${NC}"
    read -rp "➡️  Domain (e.g. mydomain.local): " DOMAIN
    read -rp "➡️  DNS server IP (e.g. 192.168.1.10): " SERVER_IP
    read -rp "➡️  Network for reverse zone (e.g. 192.168.1.0): " NETWORK

    ZONE_FILE="/etc/bind/db.${DOMAIN}"
    REV_ZONE_FILE="/etc/bind/db.${NETWORK}.${DOMAIN}"
    OCTET=$(echo $SERVER_IP | awk -F. '{print $4}')

    echo -e "${YELLOW}📄 Creating configuration files for $DOMAIN...${NC}"

    # 3️⃣ Add zone to named.conf.local
    sudo tee -a /etc/bind/named.conf.local > /dev/null <<EOF

zone "$DOMAIN" {
    type master;
    file "$ZONE_FILE";
};

zone "${NETWORK}.in-addr.arpa" {
    type master;
    file "$REV_ZONE_FILE";
};
EOF

    # 4️⃣ Create forward zone file
    sudo tee $ZONE_FILE > /dev/null <<EOF
;
; Forward zone for $DOMAIN
;
\$TTL    604800
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                         2         ; Serial
                    604800         ; Refresh
                     86400         ; Retry
                   2419200         ; Expire
                    604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMAIN.
ns1     IN      A       $SERVER_IP
www     IN      A       $SERVER_IP
EOF

    # 5️⃣ Create reverse zone file
    sudo tee $REV_ZONE_FILE > /dev/null <<EOF
;
; Reverse zone for $NETWORK
;
\$TTL    604800
@       IN      SOA     ns1.$DOMAIN. admin.$DOMAIN. (
                         2         ; Serial
                    604800         ; Refresh
                     86400         ; Retry
                   2419200         ; Expire
                    604800 )       ; Negative Cache TTL
;
@       IN      NS      ns1.$DOMAIN.
$OCTET  IN      PTR     ns1.$DOMAIN.
$OCTET  IN      PTR     www.$DOMAIN.
EOF

    # 6️⃣ Verify zone configuration
    echo -e "${YELLOW}🔍 Checking zone files...${NC}"
    sudo named-checkzone $DOMAIN $ZONE_FILE
    sudo named-checkzone ${NETWORK}.in-addr.arpa $REV_ZONE_FILE
    echo -e "${GREEN}✔ Zone $DOMAIN configured successfully${NC}"
done

# 7️⃣ Restart service
echo -e "${YELLOW}🔄 Applying configuration...${NC}"
sudo named-checkconf
sudo systemctl restart bind9
sudo systemctl enable bind9

# 8️⃣ Usage instructions
echo -e "\n${CYAN}===================================================="
echo -e " ✅ All zones have been configured successfully"
echo -e "====================================================${NC}"
echo -e "${GREEN}👉 You can now test your DNS server with:${NC}"
echo -e "   dig @<SERVER_IP> www.<DOMAIN>"
echo -e "   dig @<SERVER_IP> ns1.<DOMAIN>"
echo -e "   nslookup www.<DOMAIN> <SERVER_IP>\n"

echo -e "${YELLOW}💡 Note:${NC} For other clients to use this DNS server, set its IP in their resolv.conf or network settings."


}

# Install samba server

install_samba_server() {

echo "---------------------------------------------------"
echo "----------- Configure Samba Server ----------------"
echo "---------------------------------------------------"
echo ""
# Upgrade system and the dependencias
echo "Upgrade System..."
apt update && apt upgrade -y

# Install Samba
echo "Install Samba..."
apt install samba -y

echo "==============================================================================="
echo ""
# Ask to the user the share folder`s name
read -p "What do you want to call the shared folder? " carpeta_compartida

# Ask to the user if the shared folder will be writable or not
read -p "Do you want the folder to be writable? (y/n): " escribible

# Create the shared folder
ruta_carpeta="/srv/samba/$carpeta_compartida"
mkdir -p "$ruta_carpeta"

# Apply Permissions to the shared folder
chmod 770 "$ruta_carpeta"  #Allows the owner and group to have all permissions, but denies access to others. 
chown nobody:nogroup "$ruta_carpeta"

# Configure Samba
SMB_CONF="/etc/samba/smb.conf"
echo "Configuring Samba..."

# Apply config to the smb.conf file
{
    echo ""
    echo "[$carpeta_compartida]"
    echo "   path = $ruta_carpeta"
    echo "   available = yes"
    echo "   valid users = @sambashare"
    echo "   read only = no"
    echo "   browsable = yes"
    echo "   public = yes"
    if [[ "$escribible" == "y" || "$escribible" == "Y" ]]; then
        echo "   writable = yes"
    else
        echo "   writable = no"
    fi
} >> "$SMB_CONF"

# Esto a lo mejor se cambia
# Create a group for the samba users
groupadd sambashare

# Create a Samba user (if it does not exist)
read -p "Input the Username for Samba: " usuario
useradd -m -G sambashare "$usuario"
echo "$usuario:1234" | chpasswd  # Establecer una contraseña por defecto (puede cambiarse)
smbpasswd -a "$usuario"  # Agregar el usuario a Samba
smbpasswd -e "$usuario"  # Habilitar el usuario en Samba

#Restart Samba service
systemctl restart smbd
systemctl enable smbd

# Verify Samba Service
if systemctl is-active --quiet smbd; then
    echo "The Samba service is runs correctly."
else
    echo "Samba Server not runs."
    exit 1
fi

# Show the shared folder and configuration
echo "====================================================================================="
echo "======= The shared folder '$carpeta_compartida' has been shared correctly. =========="
echo "============= Shared Folder: //$HOSTNAME/$carpeta_compartida ========================"
echo "====================================================================================="
}

backup_or_restore_backup_from_ssh_server() {

# Log file
LOG_FILE="$HOME/backup.log"

# Function to create a backup of a directory
backup() {
    read -r -p "Enter the directory to back up: " BACKUP_DIR
    read -r -p "Enter the local folder to store the backup (If it doesn't exist, it will be created automatically): " DEST_DIR

    if [ ! -d "$BACKUP_DIR" ]; then
        echo "Error: The directory '$BACKUP_DIR' does not exist."
        exit 1
    fi

    mkdir -p "$DEST_DIR"

    BACKUP_FILE="$DEST_DIR/backup_$(date +'%Y%m%d_%H%M%S').tar.xz"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Starting backup..." | tee -a "$LOG_FILE"
    tar -cJf "$BACKUP_FILE" "$BACKUP_DIR"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Backup created: $BACKUP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error creating the backup" | tee -a "$LOG_FILE"
        exit 1
    fi

    read -r -p "Do you want to send the backup to a remote server? (y/n): " RESPONSE
    if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
        send_to_remote "$BACKUP_FILE"
    fi
}

# Function to create a database backup
backup_database() {
    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter database name: " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST
    read -r -p "Enter the local folder to store the backup: " DEST_DIR

    DB_HOST=${DB_HOST:-localhost}
    mkdir -p "$DEST_DIR"

    BACKUP_FILE="$DEST_DIR/db_backup_${DB_NAME}_$(date +'%Y%m%d_%H%M%S').sql.gz"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Starting database backup..." | tee -a "$LOG_FILE"
    mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" | gzip > "$BACKUP_FILE"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database backup created: $BACKUP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error creating the database backup" | tee -a "$LOG_FILE"
        exit 1
    fi

    read -r -p "Do you want to send the backup to a remote server? (y/n): " RESPONSE
    if [[ "$RESPONSE" =~ ^[Yy]$ ]]; then
        send_to_remote "$BACKUP_FILE"
    fi
}

# Function to restore a database from a local backup
restore_database() {
    read -r -p "Enter the path to the .sql.gz backup file: " BACKUP_FILE
    if [ ! -f "$BACKUP_FILE" ]; then
        echo "Error: File '$BACKUP_FILE' does not exist."
        exit 1
    fi

    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter the name of the database to restore into (must already exist): " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST

    DB_HOST=${DB_HOST:-localhost}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring database from backup..." | tee -a "$LOG_FILE"
    gunzip -c "$BACKUP_FILE" | mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database '$DB_NAME' successfully restored." | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the database." | tee -a "$LOG_FILE"
        exit 1
    fi
}

# Function to restore a database from a remote server
restore_database_from_remote() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the .sql.gz file on the remote server: " REMOTE_FILE
    read -r -p "Enter MySQL/MariaDB user: " DB_USER
    read -r -s -p "Enter password: " DB_PASS
    echo
    read -r -p "Enter the target database name (must already exist): " DB_NAME
    read -r -p "Enter host (default is localhost): " DB_HOST

    REMOTE_PORT=${REMOTE_PORT:-22}
    DB_HOST=${DB_HOST:-localhost}

    TEMP_FILE="$HOME/$(basename "$REMOTE_FILE")"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading database backup from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$TEMP_FILE"

    if [ $? -ne 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the file" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring database from $TEMP_FILE..." | tee -a "$LOG_FILE"
    gunzip < "$TEMP_FILE" | mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Database successfully restored from $TEMP_FILE" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the database" | tee -a "$LOG_FILE"
    fi
}

# Function to send a file to a remote server
send_to_remote() {
    FILE_TO_SEND="$1"
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path on the remote server to store the file: " REMOTE_PATH

    REMOTE_PORT=${REMOTE_PORT:-22}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Checking connection to $REMOTE_HOST on port $REMOTE_PORT..." | tee -a "$LOG_FILE"
    if ! nc -z "$REMOTE_HOST" "$REMOTE_PORT"; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error: Could not connect to $REMOTE_HOST on port $REMOTE_PORT." | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Sending file to $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$FILE_TO_SEND" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_PATH"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - File successfully sent" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error sending the file" | tee -a "$LOG_FILE"
    fi
}

# Function to restore a file-based backup from a remote server
restore_backup() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the backup file on the remote server: " REMOTE_FILE
    read -r -p "Enter the folder where the backup should be restored: " RESTORE_DIR

    REMOTE_PORT=${REMOTE_PORT:-22}

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading backup from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$HOME"

    if [ $? -eq 0 ]; then
        BACKUP_FILENAME=$(basename "$REMOTE_FILE")
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Backup successfully downloaded: $HOME/$BACKUP_FILENAME" | tee -a "$LOG_FILE"

        echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoring backup to $RESTORE_DIR..." | tee -a "$LOG_FILE"
        mkdir -p "$RESTORE_DIR"
        tar -xJf "$HOME/$BACKUP_FILENAME" -C "$RESTORE_DIR"

        if [ $? -eq 0 ]; then
            echo "$(date +"%Y-%m-%d %H:%M:%S") - Restoration completed in $RESTORE_DIR" | tee -a "$LOG_FILE"
        else
            echo "$(date +"%Y-%m-%d %H:%M:%S") - Error restoring the backup" | tee -a "$LOG_FILE"
        fi
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the backup" | tee -a "$LOG_FILE"
    fi
}

# Function to download a file from a remote server
download_file() {
    read -r -p "Enter the remote server user: " REMOTE_USER
    read -r -p "Enter the remote server IP or domain: " REMOTE_HOST
    read -r -p "Enter the SSH port (Default is 22): " REMOTE_PORT
    read -r -p "Enter the path of the file on the remote server: " REMOTE_FILE
    read -r -p "Enter the local folder to save the file: " LOCAL_DIR

    REMOTE_PORT=${REMOTE_PORT:-22}
    mkdir -p "$LOCAL_DIR"

    echo "$(date +"%Y-%m-%d %H:%M:%S") - Downloading file from $REMOTE_HOST..." | tee -a "$LOG_FILE"
    scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_FILE" "$LOCAL_DIR"

    if [ $? -eq 0 ]; then
        echo "$(date +"%Y-%m-%d %H:%M:%S") - File successfully downloaded to $LOCAL_DIR" | tee -a "$LOG_FILE"
    else
        echo "$(date +"%Y-%m-%d %H:%M:%S") - Error downloading the file" | tee -a "$LOG_FILE"
    fi
}

# Main menu
echo "Select an option:"
echo "1) Create a backup of a directory"
echo "2) Restore a backup"
echo "3) Download a file from a remote server"
echo "4) Create a database backup"
echo "5) Restore a database from local backup"
echo "6) Restore a database from remote server"
read -r -p "Enter the option number: " OPTION

case $OPTION in
    1) backup ;;
    2) restore_backup ;;
    3) download_file ;;
    4) backup_database ;;
    5) restore_database ;;
    6) restore_database_from_remote ;;
    *) echo "Invalid option. Exiting..." ;;
esac

}

# Install and configure SFTP Server

install_ftp_server_over_ssh() {


# Prompt user for input

echo "-----------------------------------------------------------------------------------"
read -p "Enter SFTP group name: " SFTP_GROUP
read -p "Enter SFTP username: " SFTP_USER
read -p "Enter SFTP base directory (e.g., /sftp/$SFTP_USER): " SFTP_DIR
read -s -p "Enter password for $SFTP_USER: " PASSWORD
echo ""
echo "-----------------------------------------------------------------------------------"

# Validate input
if [[ -z "$SFTP_GROUP" || -z "$SFTP_USER" || -z "$PASSWORD" ]]; then
    echo "Error: All fields are required. Please restart the script and provide valid inputs."
    exit 1
fi
SFTP_DIR="${SFTP_DIR:-/sftp/$SFTP_USER}"

# Install OpenSSH if not installed
echo "Installing OpenSSH Server..."
apt update && apt install -y openssh-server || { echo "Failed to install OpenSSH Server"; exit 1; }

# Create SFTP group if it doesn't exist
if ! getent group "$SFTP_GROUP" >/dev/null; then
    echo "Creating group $SFTP_GROUP..."
    groupadd "$SFTP_GROUP" || { echo "Failed to create group"; exit 1; }
else
    echo "Group $SFTP_GROUP already exists."
fi

# Create user without SSH access
if id "$SFTP_USER" &>/dev/null; then
    echo "User $SFTP_USER already exists."
else
    echo "Creating user $SFTP_USER..."
    useradd -m -d "$SFTP_DIR" -s /usr/sbin/nologin -G "$SFTP_GROUP" "$SFTP_USER" || { echo "Failed to create user"; exit 1; }
    echo "$SFTP_USER:$PASSWORD" | chpasswd
fi

# Set permissions
echo "Setting permissions for the SFTP directory..."
mkdir -p "$SFTP_DIR/upload"
chown root:root "$SFTP_DIR"
chmod 755 "$SFTP_DIR"
chown "$SFTP_USER:$SFTP_GROUP" "$SFTP_DIR/upload"
chmod 750 "$SFTP_DIR/upload"

# Configure SSH for SFTP
echo "Configuring SSH for SFTP..."
SSHD_CONFIG="/etc/ssh/sshd_config"
if ! grep -q "Match Group $SFTP_GROUP" "$SSHD_CONFIG"; then
    echo "Match Group $SFTP_GROUP
    ChrootDirectory $SFTP_DIR
    ForceCommand internal-sftp
    X11Forwarding no
    AllowTcpForwarding no" >> "$SSHD_CONFIG"
else
    echo "SFTP configuration for group $SFTP_GROUP already exists in $SSHD_CONFIG."
fi

# Restart SSH service
echo "Restarting SSH service..."
systemctl restart ssh || { echo "Failed to restart SSH service"; exit 1; }

# Final message
echo "SFTP setup complete. User $SFTP_USER can now connect using SFTP."
echo "-----------------------------------------------------------------------------------"
echo "To connect using FileZilla:"
echo "- Host: Your server's IP address"
echo "- Username: $SFTP_USER"
echo "- Password: (the one you set)"
echo "- Port: 22"
echo "- Protocol: SFTP - SSH File Transfer Protocol"
echo "-----------------------------------------------------------------------------------"

}
# function to install Apache, PHP, MySQL server, MySQL client, Certbot, Bind9, Nextcloud, and required configurations to set up the server.

nextcloud_install(){

# Interactive menu for capturing values

echo "==========================================================="
echo "============= Nextcloud Installation ======================"
echo "==========================================================="
echo "==========================================================="
echo "================== by TheHellishPandaa  ==================="
echo "================ GitHub: TheHellishPandaa ================="
echo "==========================================================="
echo ""
# Check if the user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." 
    exit 1
fi

# Prompt for Nextcloud version
read -p "Which version of Nextcloud would you like to install? (Default: 28.0.0): " NEXTCLOUD_VERSION
NEXTCLOUD_VERSION=${NEXTCLOUD_VERSION:-"28.0.0"}  # Default version if user inputs nothing

# Prompt for database name
read -p "Enter the database name (default: nextcloud_db): " DB_NAME
DB_NAME=${DB_NAME:-"nextcloud_db"}

read -p "Input Database User (Default nextcloud_user): " DB_USER
DB_USER=${DB_USER:-"nextcloud_user"}

while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo "Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo "Error: Passwords do not match. Please try again."
    fi
done

# Prompt for Nextcloud installation path
read -p "Enter the Nextcloud installation path (default: /var/www/html/nextcloud): " NEXTCLOUD_PATH
NEXTCLOUD_PATH=${NEXTCLOUD_PATH:-"/var/www/html/nextcloud"}

# Promt Nextcloud Data Directory
 read -p "Enter the directory where Nextcloud will store data (default: /var/nextcloud/data): " DATA_DIRECTORY
 DATA_DIRECTORY=${DATA_DIRECTORY:-"/var/nextcloud/data"}

# Prompt for domain or IP
read -p "Enter the domain or IP to access Nextcloud: " DOMAIN

# Configuration confirmation

echo -e "========================================================"
echo -e "============ Configuration Summary ====================="
echo -e "========================================================"
echo -e "Nextcloud Version:     $NEXTCLOUD_VERSION"
echo -e "Database:              $DB_NAME"
echo -e "Database User:         $DB_USER"
echo -e "Installation Path:     $NEXTCLOUD_PATH"
echo -e "Data Directory:        $DATA_DIRECTORY"
echo -e "Domain or IP:          $DOMAIN"
echo -e "========================================================"

echo -e "Do you want to proceed with the installation? (y/n): "

# Confirmation to proceed with the installation
read -n 1 CONFIRM
echo
if [[ "$CONFIRM" != [yY] ]]; then
    echo "Installation canceled."
    exit 1
fi

# Rest of the script for Nextcloud installation
# Update and upgrade packages
echo "========================================================"
echo "=============== Updating system... ====================="
echo "========================================================"
apt update && apt upgrade -y

# Install Apache
echo "Installing Apache..."
apt install apache2 -y
ufw allow 'Apache Full'

# Install MariaDB
echo "Installing MariaDB..."
apt install mariadb-server -y

# Create database and user for Nextcloud
echo "Configuring database for Nextcloud..."
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Setup root user
# mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"

# Install PHP and necessary modules
echo "Installing PHP  and modules..."
sudo apt install -y php php-gd php-json php-mbstring php-curl php-xml php-zip php-mysql php-intl php-bz2 php-imagick php-fpm php-cli libapache2-mod-php php-sqlite3 php-pgsql

 # Create Data Directory
    echo "Creating Data Directory..."
    if [[ ! -d "$DATA_DIRECTORY" ]]; then
        mkdir -p "$DATA_DIRECTORY"
        echo "Data directory created at: $DATA_DIRECTORY"
    else
        echo "Data directory already exists: $DATA_DIRECTORY"
    fi
    chown -R www-data:www-data "$DATA_DIRECTORY"
    chmod -R 750 "$DATA_DIRECTORY"
    
# Configure PHP for Nextcloud
echo "Configuring PHP..."
PHP_INI_PATH=$(php -r "echo php_ini_loaded_file();")
sed -i "s/memory_limit = .*/memory_limit = 512M/" "$PHP_INI_PATH"
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 512M/" "$PHP_INI_PATH"
sed -i "s/post_max_size = .*/post_max_size = 512M/" "$PHP_INI_PATH"
sed -i "s/max_execution_time = .*/max_execution_time = 300/" "$PHP_INI_PATH"

# Download and configure Nextcloud
echo "Downloading Nextcloud..."
wget https://download.nextcloud.com/server/releases/nextcloud-${NEXTCLOUD_VERSION}.tar.bz2
tar -xjf nextcloud-${NEXTCLOUD_VERSION}.tar.bz2
mv nextcloud $NEXTCLOUD_PATH
chown -R www-data:www-data $NEXTCLOUD_PATH
chmod -R 755 $NEXTCLOUD_PATH

# Enable Nextcloud configuration and necessary Apache modules
a2ensite nextcloud.conf
a2enmod rewrite headers env dir mime setenvif
systemctl restart apache2

# Finish
echo "Nextcloud installation complete."
echo "Please access http://$DOMAIN/nextcloud to complete setup in the browser."
}

moodle_install(){
# Script that configure moodle 

echo "----------------------------------------------"
echo "-------------- MOODLE SETUP ------------------"
echo "----------------------------------------------"

# Prompt for database name
read -p "Enter the database name (default: moodle_db): " DB_NAME
DB_NAME=${DB_NAME:-"moodle_db"}

# Prompt for database user
read -p "Enter the database user name (default: moodle_user): " DB_USER
DB_USER=${DB_USER:-"moodle_user"}

read -p "What will be your data directory? (default: /var/www/moodledata): " data_directory
data_directory=${data_directory:-"/var/www/moodledata"}



# Compare passwords
while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

# Prompt Again for database password
    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    # Prompt for database password
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo "Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo "Error: Passwords do not match. Please try again."
    fi
done

# Prompt for installation path
read -p "Enter the moodle installation path (default: /var/www/html/moodle): " MOODLE_PATH
MOODLE_PATH=${MOODLE_PATH:-"/var/www/html/moodle"}


# Prompt for domain or IP
read -p "Enter the domain or IP to access Moodle: " DOMAIN


# Configuration confirmation
echo -e ""
echo -e "========================================================"
echo -e "============ Configuration Summary: ===================="
echo -e "========================================================"
echo -e ""

echo "Database: $DB_NAME"
echo "Database User: Root"
echo "Installation Path: $MOODLE_PATH"
echo "Domain or IP: $DOMAIN"
echo "Data Directory: " $data_directory
echo -e "Do you want to proceed with the installation? (y/n): "

# Confirmation to proceed with the installation
read -n 1 CONFIRM
echo
if [[ "$CONFIRM" != [yY] ]]; then
    echo "Installation canceled."
    exit 1
fi

# Rest of the script for Moodle installation
# Update and upgrade packages
echo "========================================================"
echo "=============== Updating system... ====================="
echo "========================================================"
apt update && apt upgrade -y

# Install Apache
echo "Installing Apache..."
apt install apache2 -y
ufw allow 'Apache Full'

# Install MariaDB
echo "Installing MariaDB..."
apt install mariadb-server -y
mysql_secure_installation

# Create database and user for moodle
echo "Configuring database for Moodle.."
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Install PHP and necessary modules
echo "Installing PHP  and modules..."
sudo apt install -y php php-gd php-json php-mbstring php-curl php-xml php-zip php-mysql php-intl php-bz2 php-imagick php-fpm php-cli libapache2-mod-php php-sqlite3 php-pgsql git
sudo apt update
sudo apt install php-curl php-zip

# Configure PHP
echo "Configuring PHP..."
PHP_INI_PATH=$(php -r "echo php_ini_loaded_file();")
sed -i "s/memory_limit = .*/memory_limit = 512M/" "$PHP_INI_PATH"
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 512M/" "$PHP_INI_PATH"
sed -i "s/post_max_size = .*/post_max_size = 512M/" "$PHP_INI_PATH"
sed -i "s/max_execution_time = .*/max_execution_time = 300/" "$PHP_INI_PATH"


# Download and configure Moodle
echo "Downloading Moodle..."
sudo apt install git
sudo apt install php-xml
sudo apt install php-mbstring
sudo apt install php-mysqli

git clone https://github.com/moodle/moodle.git
mv moodle $MOODLE_PATH
chown -R www-data:www-data $MOODLE_PATH
chmod -R 755 $MOODLE_PATH

# Make the Moodle data directory

mkdir $data_directory
chown -R www-data:www-data $data_directory
chmod -R 755 $data_directory

# Restart Apache web server
systemctl restart apache2

# Finish
echo "---------------------------------------------------------------------"
echo "Moodle installation complete."
echo "Please access http://$DOMAIN/moodle to complete setup in the browser."
echo "---------------------------------------------------------------------"
}
wp_install() {

# Enable strict mode: stop script execution if any command fails
set -e

# Define variables
WP_URL="https://wordpress.org/latest.tar.gz"
WP_ARCHIVE="latest.tar.gz"
WP_DIR="/var/www/html/wordpress"

# Ask user for database details
read -p "Enter the database name: " DB_NAME
read -p "Enter the database username: " DB_USER
read -s -p "Enter the database password: " DB_PASSWORD

# Prompt again to verify password
read -sp "Re-enter the password to verify: " DB_PASSWORD2
echo


while true; do
# Start an infinite loop to keep prompting until the password is confirmed 

    read -sp "Enter the password for the database user: " DB_PASSWORD
    echo
    read -sp "Re-enter the password to verify: " DB_PASSWORD2
    echo

 # Compare the two passwords
 
    if [ "$DB_PASSWORD" == "$DB_PASSWORD2" ]; then
    # If they match, confirm success and break out of the loop
    
        echo "Password confirmed."
        break
    else
     # If they don't match, show an error and prompt again
     
        echo "Error: Passwords do not match. Please try again."
    fi
done

# Display installation details
echo ""
echo "🔹 WordPress will be installed with the following settings:"
echo "   📂 Download and extraction in: $(pwd)"
echo "   🚀 Installation in: $WP_DIR"
echo "   💾 Database name: $DB_NAME"
echo "   👤 Database user: $DB_USER"
echo ""
read -p "❓ Do you want to continue? (y/n): " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
    echo "❌ Installation canceled."
    exit 1
fi

# Update system
echo "🔄 Updating packages..."
sudo apt update && sudo apt upgrade -y

# Install Apache
echo "🌍 Installing Apache..."
sudo apt install -y apache2

echo "💾 Installing MariaDB..."
sudo apt update
sudo apt install -y mariadb-server
sudo systemctl enable --now mariadb

# Configure MARIADB (create DB and user)
echo "🛠 Configuring Mariadb..."
sudo mysql -e "CREATE DATABASE $DB_NAME;"
sudo mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
sudo mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Install PHP and required modules
echo "🐘 Installing PHP and modules..."
sudo apt install -y php libapache2-mod-php php-mysql php-curl php-gd php-mbstring php-xml php-xmlrpc php-soap php-intl php-zip

# Download and extract WordPress in the script's directory
echo "⬇ Downloading WordPress in $(pwd)..."
wget -q $WP_URL -O $WP_ARCHIVE
tar -xzf $WP_ARCHIVE

# Move WordPress to /var/www/html
echo "📂 Moving WordPress to $WP_DIR..."
sudo mv wordpress $WP_DIR

# Set permissions
echo "🔑 Setting permissions..."
sudo chown -R www-data:www-data $WP_DIR
sudo chmod -R 755 $WP_DIR

# Configure wp-config.php automatically
echo "⚙ Configuring WordPress..."
sudo cp $WP_DIR/wp-config-sample.php $WP_DIR/wp-config.php
sudo sed -i "s/database_name_here/$DB_NAME/" $WP_DIR/wp-config.php
sudo sed -i "s/username_here/$DB_USER/" $WP_DIR/wp-config.php
sudo sed -i "s/password_here/$DB_PASS/" $WP_DIR/wp-config.php

echo "------------------------------------------------------------"
echo "-----------------------------------------"
echo ""
echo "   💾 database name: $DB_NAME"
echo "   👤 database user: $DB_USER"
echo ""
echo "-----------------------------------------"
echo "------------------------------------------------------------"

# Cleanup
echo "🧹 Removing installation archive..."
rm -f $WP_ARCHIVE

echo "✅ Installation complete. Access http://your-server/wordpress to finish WordPress setup."

}



configure_prometheus () {


# Variables
PROM_VERSION="2.51.2"
PROM_USER="prometheus"
PROM_DIR="/etc/prometheus"
PROM_DATA_DIR="/var/lib/prometheus"
PROM_BIN_DIR="/usr/local/bin"
NODE_EXPORTER_VERSION="1.7.0"

install_prometheus() {
    echo "Updating system and installing dependencies..."
    apt update && apt install -y wget tar || { echo "Failed to install dependencies"; exit 1; }
    
    echo "Creating Prometheus user..."
    useradd --no-create-home --shell /bin/false $PROM_USER
    
    echo "Creating directories..."
    mkdir -p $PROM_DIR $PROM_DATA_DIR
    chown $PROM_USER:$PROM_USER $PROM_DIR $PROM_DATA_DIR
    
    echo "Downloading Prometheus v$PROM_VERSION..."
    wget https://github.com/prometheus/prometheus/releases/download/v$PROM_VERSION/prometheus-$PROM_VERSION.linux-amd64.tar.gz -O /tmp/prometheus.tar.gz
    
    echo "Extracting Prometheus..."
    tar -xzf /tmp/prometheus.tar.gz -C /tmp/
    cd /tmp/prometheus-$PROM_VERSION.linux-amd64/
    
    echo "Installing Prometheus binaries..."
    mv prometheus promtool $PROM_BIN_DIR/
    chown $PROM_USER:$PROM_USER $PROM_BIN_DIR/prometheus $PROM_BIN_DIR/promtool
    
    echo "Setting up configuration..."
    mv prometheus.yml $PROM_DIR/
    chown $PROM_USER:$PROM_USER $PROM_DIR/prometheus.yml
    
    echo "Creating Prometheus systemd service..."
    cat <<EOF > /etc/systemd/system/prometheus.service
[Unit]
Description=Prometheus Monitoring System
Wants=network-online.target
After=network-online.target

[Service]
User=$PROM_USER
Group=$PROM_USER
Type=simple
ExecStart=$PROM_BIN_DIR/prometheus \\
    --config.file=$PROM_DIR/prometheus.yml \\
    --storage.tsdb.path=$PROM_DATA_DIR \\
    --web.listen-address=0.0.0.0:9090 \\
    --storage.tsdb.retention.time=15d

[Install]
WantedBy=multi-user.target
EOF
    
    echo "Starting Prometheus service..."
    systemctl daemon-reload
    systemctl enable --now prometheus.service
    echo "Prometheus installation complete! Running on port 9090"
    echo "Directory of prometheus: $PROM_DIR"
}

install_node_exporter() {


set -e  # Stop script on error

# Update the system
sudo apt update && sudo apt upgrade -y

# Install required dependencies
sudo apt install -y wget tar curl

# Get the latest Node Exporter version dynamically
NODE_EXPORTER_VERSION=$(curl -s https://api.github.com/repos/prometheus/node_exporter/releases/latest | grep -oP '"tag_name": "v\K[0-9.]+')

# Check if Node Exporter is already installed
if command -v node_exporter &> /dev/null; then
    echo "Node Exporter is already installed. Skipping installation."
    exit 0
fi

# Download Node Exporter
wget https://github.com/prometheus/node_exporter/releases/download/v$NODE_EXPORTER_VERSION/node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz

# Extract the downloaded file
tar -xvzf node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz

# Move the binary to /usr/local/bin
sudo mv node_exporter-$NODE_EXPORTER_VERSION.linux-amd64/node_exporter /usr/local/bin/

# Remove downloaded files to save space
rm -rf node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz node_exporter-$NODE_EXPORTER_VERSION.linux-amd64

# Ensure the user exists
if ! id "node_exporter" &>/dev/null; then
    sudo useradd -rs /bin/false node_exporter
fi

# Create a systemd service for Node Exporter
cat << EOF | sudo tee /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
After=network.target

[Service]
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=default.target
EOF

# Reload systemd daemon and enable the service
sudo systemctl daemon-reload
sudo systemctl enable node_exporter
sudo systemctl start node_exporter

# Check if Node Exporter is running
sudo systemctl status node_exporter --no-pager

echo "-----------------------------------"
echo " ✅ Node Exporter installed and running on port 9100"
echo "-----------------------------------"

}

add_node_exporter_to_prometheus() {
    read -p "Enter the IP address of the Node Exporter: " NODE_EXPORTER_IP
    read -p "Enter the job name for Node Exporter: " JOB_NAME
    echo "Adding Node Exporter job to prometheus.yml..."
    cat <<EOF >> $PROM_DIR/prometheus.yml

  - job_name: '$JOB_NAME'
    static_configs:
      - targets: ['$NODE_EXPORTER_IP:9100']
EOF
    echo "Node Exporter job '$JOB_NAME' added to Prometheus configuration. Restarting Prometheus..."
    systemctl restart prometheus.service
}

# Menu for installation
echo "--------------------------------------------------"
echo "Choose an option:"
echo "1) Install Prometheus"
echo "2) Install Node Exporter"
echo "3) Add Node Exporter to Prometheus"
echo "4) Exit"
echo "--------------------------------------------------"
read -p "Enter your choice: " CHOICE

case $CHOICE in
    1)
        install_prometheus
        ;;
    2)
        install_node_exporter
        ;;
    3)
        add_node_exporter_to_prometheus
        ;;
    4)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac


# Final message
echo "--------------------------------------------------"
echo "Installation process complete!"
echo "--------------------------------------------------"

}
configure_graphana () {

# Starting message
echo "Starting Grafana installation."

# Update system repositories
echo "Updating system repositories..."
apt update && apt upgrade -y

# Install necessary dependencies
echo "Installing necessary dependencies..."
apt install -y software-properties-common wget

# Add the official Grafana repository
echo "Adding the official Grafana repository..."
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | tee -a /etc/apt/sources.list.d/grafana.list

# Update repositories after adding Grafana
echo "Updating repositories after adding Grafana..."
apt update

# Install Grafana
echo "Installing Grafana..."
apt install -y grafana

# Verify installation
if [ $? -eq 0 ]; then
    echo "Grafana installed successfully."
else
    echo "There was a problem installing Grafana. Please check the errors."
    exit 1
fi

# Start and enable the Grafana service
echo "Starting the Grafana service..."
systemctl start grafana-server
systemctl enable grafana-server

# Verify the status of Grafana
echo "Checking the Grafana service status..."
systemctl status grafana-server --no-pager | grep -i 'active'

# Final message
echo "----------------------------------------------------------------------------------"
echo "Grafana has been successfully installed on the server!"
echo "You can access the Grafana web interface at http://<YOUR-SERVER-IP>:3000."
echo "Default username: admin"
echo "Default password: admin"

# Warning message for first login
echo "Remember to change the password on the first login."
echo "-----------------------------------------------------------------------------------"

}

setup_virtualhost () {


# Ask user for domain name
read -p "Enter your domain name: " DOMAIN

# Ask user for document root
read -p "Enter your document root (default: /var/www/html/$DOMAIN): " DOC_ROOT
DOC_ROOT=${DOC_ROOT:-/var/www/html/$DOMAIN}

# Ask user if they want SSL
read -p "Do you want to enable SSL? (y/n): " ENABLE_SSL
CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN.conf
SSL_CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN-ssl.conf

sudo chown -R $USER:$USER $DOC_ROOT
sudo chmod -R 755 /var/www/html

# Create virtual host configuration
sudo tee $CONFIG_FILE > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@$DOMAIN
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot $DOC_ROOT
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-access.log combined
</VirtualHost>
EOF

# Enable SSL if chosen
if [ "$ENABLE_SSL" == "y" ]; then
    sudo tee $SSL_CONFIG_FILE > /dev/null <<EOF
<VirtualHost *:443>
    ServerAdmin webmaster@$DOMAIN
    ServerName $DOMAIN
    ServerAlias www.$DOMAIN
    DocumentRoot $DOC_ROOT
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/$DOMAIN.crt
    SSLCertificateKeyFile /etc/ssl/private/$DOMAIN.key
    ErrorLog \${APACHE_LOG_DIR}/$DOMAIN-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/$DOMAIN-ssl-access.log combined
</VirtualHost>
EOF
    sudo a2enmod ssl
    sudo a2ensite $DOMAIN-ssl.conf
fi

# Enable the site and reload Apache
sudo a2ensite $DOMAIN.conf
sudo systemctl reload apache2

# Output success message
echo "Virtual host for $DOMAIN has been created successfully!"
if [ "$ENABLE_SSL" == "y" ]; then
    echo "SSL has been enabled for $DOMAIN. Make sure to place your certificate files in /etc/ssl/certs/ and /etc/ssl/private/."
fi
}

network_scan() {

# Function to scan the local network and display connected devices
scan_network() {

      #show interfaces
            echo ""
            echo "++++++++++++++++++++++++++++++++"
            echo "Available interfaces"
            echo "++++++++++++++++++++++++++++++++"
            INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
            echo "$INTERFACES"
            echo "++++++++++++++++++++++++++++++++"
            echo ""
            read -p "What interface wwould use to scan: " interface

    echo "Scanning devices on the local network using interface $interface..."
    echo ""

    # Use arp-scan to get connected devices
    if command -v arp-scan > /dev/null 2>&1; then
        sudo arp-scan --interface="$interface" --localnet
    else
        echo "arp-scan is not installed. Installing it..."
        sudo apt update && sudo apt install -y arp-scan
        sudo arp-scan --interface="$interface" --localnet
    fi
}

# Interactive menu
while true; do
    echo ""
    echo "--- Connected Devices Scan ---"
    echo "1. Scan the local network"
    echo "2. Exit"
    read -p "Select an option: " option

    case $option in
        1) scan_network ;;
        2) echo "Exiting..."; exit 1 ;;
        *) echo "Invalid option. Please try again." ;;
    esac
done
}

show_system_info () {
# Show a welcome message
echo "*******************************************************************"
echo "****** MONITORING CPU, MEMORY, DISK AND NETWORK INFORMATION *******"
echo "*******************************************************************"

echo "To run this script successfully, please ensure 'curl' is installed. You can install it using: 'snap install curl' or 'apt install curl'"
echo

# Function to get the hostname
get_HOSTNAME() {
    HOSTNAME=$(cat /etc/hostname)
}

# Function to get CPU usage
get_cpu_usage() {
    echo "CPU USAGE:"
    top -bn1 | grep "Cpu(s)" | awk '{printf "CPU in use: %.2f%%\n", $2 + $4}'
}

# Function to get memory usage in GB
get_memory_usage() {
    echo "MEMORY USAGE:"
    free -m | grep Mem | awk '{printf "Memory used: %.2fGB of %.2fGB\n", $3/1024, $2/1024}'
}

# Function to get disk usage
get_disk_usage() {
    echo "DISK USAGE:"
    df -h / | grep / | awk '{print "Disk usage: " $5 " (" $3 " used of " $2 ")"}'
}

# Function to get swap memory usage
get_swap_usage() {
    echo "SWAP USAGE:"
    free -m | grep Swap | awk '{printf "Swap used: %.2fGB of %.2fGB\n", $3/1024, $2/1024}'
}

# Function to get the network interface in use
get_network_interface() {
    interfaz=$(ip route | grep '^default' | awk '{print $5}')
    if [[ -z "$interfaz" ]]; then
        echo "A network interface could not be detected."
        return 1
    fi
    echo "Your network interface is: $interfaz"
}

# Function to get local IP
get_local_ip() {
    echo "LOCAL IP:"
    hostname -I
}

# Function to get MAC address
get_DIR_MAC() {
    echo "MAC ADDRESS:"
    interfaz=$(ip route | grep '^default' | awk '{print $5}')
    cat /sys/class/net/$interfaz/address
}

# Function to get the default gateway
get_DEFAULT_GATEWAY() {
    echo "DEFAULT GATEWAY:"
    ip route show default
}

# Function to get the public IP
get_public_ip() {
    echo "PUBLIC IP:"
    PUBLIC_IP=$(curl -s ifconfig.me)
    if [[ -n "$PUBLIC_IP" ]]; then
        echo "Public IP: $PUBLIC_IP"
    else
        echo "Could not obtain your Public IP Address. Check your Internet connection."
    fi
}

# Function to check internet connection
get_INTERNET_CONNECTION() {
    echo "INTERNET CONNECTION:"
    var=$(curl -s --head http://www.google.com | head -n 1)
    if [[ $var == *"200 OK"* ]]; then
        echo "Internet Connection: Active"
    else
        echo "No internet connection detected. Please check your network adapter and rerun the script."
    fi
}

# Get system information
echo "-----------------------------------"
echo "The Hostname of the system is: $HOSTNAME"
echo "-----------------------------------"
get_cpu_usage
echo "-----------------------------------"
get_memory_usage
echo "-----------------------------------"
get_disk_usage
echo "-----------------------------------"
get_swap_usage
echo "-----------------------------------"
get_network_interface
echo "-----------------------------------"
get_local_ip
echo "-----------------------------------"
get_DIR_MAC
echo "-----------------------------------"
get_DEFAULT_GATEWAY
echo "-----------------------------------"
get_public_ip
echo "-----------------------------------"
get_INTERNET_CONNECTION
echo "-----------------------------------"


} 

# Función para gestionar Certbot (instalar, ver, eliminar)
manage_certbot() {
  while true; do
    clear
    echo "=== Certbot SSL Certificate Manager ==="
    echo "1) Install SSL certificate"
    echo "2) Show existing certificates"
    echo "3) Delete SSL certificate"
    echo "4) Back to main menu"
    echo "======================================="
    read -p "Select an option [1-4]: " choice

    case $choice in
      1)
        read -p "Enter the domain for the SSL certificate: " domain
        read -p "Enter your email address: " email

        echo "Updating repositories and upgrading system..."
        apt update && apt upgrade -y || { echo "Failed to update system"; return; }

        echo "Installing Certbot..."
        apt install -y certbot || { echo "Failed to install Certbot"; return; }

        echo "Select your web server:"
        echo "1) Apache"
        echo "2) Nginx"
        read -p "Choice [1-2]: " web_server

        case $web_server in
          1)
            apt install -y python3-certbot-apache || { echo "Failed to install Apache plugin"; return; }
            certbot --apache -d "$domain" --email "$email" --agree-tos --no-eff-email
            ;;
          2)
            apt install -y python3-certbot-nginx || { echo "Failed to install Nginx plugin"; return; }
            certbot --nginx -d "$domain" --email "$email" --agree-tos --no-eff-email
            ;;
          *)
            echo "Invalid web server option. Returning..."
            return
            ;;
        esac

        echo "✅ SSL certificate installed successfully for $domain."
        read -p "Press enter to continue..." ;;
      
      2)
        echo "📋 Listing installed SSL certificates..."
        certbot certificates || echo "⚠️ No certificates found or Certbot is not installed."
        read -p "Press enter to continue..." ;;
      
      3)
        read -p "Enter the domain name of the certificate to delete: " domain
        certbot delete --cert-name "$domain"
        read -p "Press enter to continue..." ;;
      
      4)
        break ;;
      
      *)
        echo "Invalid option. Please try again."
        sleep 2 ;;
    esac
  done
}
setup_open_vpn(){
# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing, you can continue at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, you can continue at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ${VERSION_ID%.*} -lt 7 ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only supports CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only supports Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ $VERSION_ID == "2" ]]; then
				OS="amzn"
			elif [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
				OS="amzn2023"
			else
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only supports Amazon Linux 2 or Amazon Linux 2023.6+"
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "It looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system."
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this script as root."
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available."
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# If Unbound isn't installed, install it
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Configuration
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS for all OS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function resolvePublicIP() {
	# IP version flags, we'll use as default the IPv4
	CURL_IP_VERSION_FLAG="-4"
	DIG_IP_VERSION_FLAG="-4"

	# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
	if [[ $IPV6_SUPPORT == "y" ]]; then
		CURL_IP_VERSION_FLAG=""
		DIG_IP_VERSION_FLAG="-6"
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.seeip.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.seeip.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://ifconfig.me
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://ifconfig.me 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: https://api.ipify.org
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(curl -f -m 5 -sS --retry 2 --retry-connrefused "$CURL_IP_VERSION_FLAG" https://api.ipify.org 2>/dev/null)
	fi

	# If there is no public ip yet, we'll try to solve it using: ns1.google.com
	if [[ -z $PUBLIC_IP ]]; then
		PUBLIC_IP=$(dig $DIG_IP_VERSION_FLAG TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	if [[ -z $PUBLIC_IP ]]; then
		echo >&2 echo "Couldn't solve the public IP"
		exit 1
	fi

	echo "$PUBLIC_IP"
}

function installQuestions() {
	echo "Welcome to the OpenVPN installer!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""

	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are okay with them."
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		read -rp "IP address: " -e -i "$IP" IP
	fi
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIP)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "Public IPv4 address or hostname: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi
	echo ""
	# Ask the user if they want to enable IPv6 regardless its availability.
	until [[ $IPV6_SUPPORT =~ (y|n) ]]; do
		read -rp "Do you want to enable IPv6 support (NAT)? [y/n]: " -e -i $SUGGESTION IPV6_SUPPORT
	done
	echo ""
	echo "What port do you want OpenVPN to listen to?"
	echo "   1) Default: 1194"
	echo "   2) Custom"
	echo "   3) Random [49152-65535]"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "Port choice [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT="1194"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "Custom port [1-65535]: " -e -i 1194 PORT
		done
		;;
	3)
		# Generate random number within private ports range
		PORT=$(shuf -i49152-65535 -n1)
		echo "Random Port: $PORT"
		;;
	esac
	echo ""
	echo "What protocol do you want OpenVPN to use?"
	echo "UDP is faster. Unless it is not available, you shouldn't use TCP."
	echo "   1) UDP"
	echo "   2) TCP"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "Protocol [1-2]: " -e -i 1 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	echo ""
	echo "What DNS resolvers do you want to use with the VPN?"
	echo "   1) Current system resolvers (from /etc/resolv.conf)"
	echo "   2) Self-hosted DNS Resolver (Unbound)"
	echo "   3) Cloudflare (Anycast: worldwide)"
	echo "   4) Quad9 (Anycast: worldwide)"
	echo "   5) Quad9 uncensored (Anycast: worldwide)"
	echo "   6) FDN (France)"
	echo "   7) DNS.WATCH (Germany)"
	echo "   8) OpenDNS (Anycast: worldwide)"
	echo "   9) Google (Anycast: worldwide)"
	echo "   10) Yandex Basic (Russia)"
	echo "   11) AdGuard DNS (Anycast: worldwide)"
	echo "   12) NextDNS (Anycast: worldwide)"
	echo "   13) Custom"
	until [[ $DNS =~ ^[0-9]+$ ]] && [ "$DNS" -ge 1 ] && [ "$DNS" -le 13 ]; do
		read -rp "DNS [1-12]: " -e -i 11 DNS
		if [[ $DNS == 2 ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			echo ""
			echo "Unbound is already installed."
			echo "You can allow the script to configure it in order to use it from your OpenVPN clients"
			echo "We will simply add a second server to /etc/unbound/unbound.conf for the OpenVPN subnet."
			echo "No changes are made to the current configuration."
			echo ""

			until [[ $CONTINUE =~ (y|n) ]]; do
				read -rp "Apply configuration changes to Unbound? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				# Break the loop and cleanup
				unset DNS
				unset CONTINUE
			fi
		elif [[ $DNS == "13" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Primary DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "Secondary DNS (optional): " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
		fi
	done
	echo ""
	echo "Do you want to use compression? It is not recommended since the VORACLE attack makes use of it."
	until [[ $COMPRESSION_ENABLED =~ (y|n) ]]; do
		read -rp"Enable compression? [y/n]: " -e -i n COMPRESSION_ENABLED
	done
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "Choose which compression algorithm you want to use: (they are ordered by efficiency)"
		echo "   1) LZ4-v2"
		echo "   2) LZ4"
		echo "   3) LZ0"
		until [[ $COMPRESSION_CHOICE =~ ^[1-3]$ ]]; do
			read -rp"Compression algorithm [1-3]: " -e -i 1 COMPRESSION_CHOICE
		done
		case $COMPRESSION_CHOICE in
		1)
			COMPRESSION_ALG="lz4-v2"
			;;
		2)
			COMPRESSION_ALG="lz4"
			;;
		3)
			COMPRESSION_ALG="lzo"
			;;
		esac
	fi
	echo ""
	echo "Do you want to customize encryption settings?"
	echo "Unless you know what you're doing, you should stick with the default parameters provided by the script."
	echo "Note that whatever you choose, all the choices presented in the script are safe (unlike OpenVPN's defaults)."
	echo "See https://github.com/angristan/openvpn-install#security-and-encryption to learn more."
	echo ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "Customize encryption settings? [y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	else
		echo ""
		echo "Choose which cipher you want to use for the data channel:"
		echo "   1) AES-128-GCM (recommended)"
		echo "   2) AES-192-GCM"
		echo "   3) AES-256-GCM"
		echo "   4) AES-128-CBC"
		echo "   5) AES-192-CBC"
		echo "   6) AES-256-CBC"
		until [[ $CIPHER_CHOICE =~ ^[1-6]$ ]]; do
			read -rp "Cipher [1-6]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		esac
		echo ""
		echo "Choose what kind of certificate you want to use:"
		echo "   1) ECDSA (recommended)"
		echo "   2) RSA"
		until [[ $CERT_TYPE =~ ^[1-2]$ ]]; do
			read -rp"Certificate key type [1-2]: " -e -i 1 CERT_TYPE
		done
		case $CERT_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the certificate's key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			until [[ $CERT_CURVE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp"Curve [1-3]: " -e -i 1 CERT_CURVE_CHOICE
			done
			case $CERT_CURVE_CHOICE in
			1)
				CERT_CURVE="prime256v1"
				;;
			2)
				CERT_CURVE="secp384r1"
				;;
			3)
				CERT_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose which size you want to use for the certificate's RSA key:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $RSA_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "RSA key size [1-3]: " -e -i 1 RSA_KEY_SIZE_CHOICE
			done
			case $RSA_KEY_SIZE_CHOICE in
			1)
				RSA_KEY_SIZE="2048"
				;;
			2)
				RSA_KEY_SIZE="3072"
				;;
			3)
				RSA_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose which cipher you want to use for the control channel:"
		case $CERT_TYPE in
		1)
			echo "   1) ECDHE-ECDSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-ECDSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		2)
			echo "   1) ECDHE-RSA-AES-128-GCM-SHA256 (recommended)"
			echo "   2) ECDHE-RSA-AES-256-GCM-SHA384"
			until [[ $CC_CIPHER_CHOICE =~ ^[1-2]$ ]]; do
				read -rp"Control channel cipher [1-2]: " -e -i 1 CC_CIPHER_CHOICE
			done
			case $CC_CIPHER_CHOICE in
			1)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
				;;
			2)
				CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384"
				;;
			esac
			;;
		esac
		echo ""
		echo "Choose what kind of Diffie-Hellman key you want to use:"
		echo "   1) ECDH (recommended)"
		echo "   2) DH"
		until [[ $DH_TYPE =~ [1-2] ]]; do
			read -rp"DH key type [1-2]: " -e -i 1 DH_TYPE
		done
		case $DH_TYPE in
		1)
			echo ""
			echo "Choose which curve you want to use for the ECDH key:"
			echo "   1) prime256v1 (recommended)"
			echo "   2) secp384r1"
			echo "   3) secp521r1"
			while [[ $DH_CURVE_CHOICE != "1" && $DH_CURVE_CHOICE != "2" && $DH_CURVE_CHOICE != "3" ]]; do
				read -rp"Curve [1-3]: " -e -i 1 DH_CURVE_CHOICE
			done
			case $DH_CURVE_CHOICE in
			1)
				DH_CURVE="prime256v1"
				;;
			2)
				DH_CURVE="secp384r1"
				;;
			3)
				DH_CURVE="secp521r1"
				;;
			esac
			;;
		2)
			echo ""
			echo "Choose what size of Diffie-Hellman key you want to use:"
			echo "   1) 2048 bits (recommended)"
			echo "   2) 3072 bits"
			echo "   3) 4096 bits"
			until [[ $DH_KEY_SIZE_CHOICE =~ ^[1-3]$ ]]; do
				read -rp "DH key size [1-3]: " -e -i 1 DH_KEY_SIZE_CHOICE
			done
			case $DH_KEY_SIZE_CHOICE in
			1)
				DH_KEY_SIZE="2048"
				;;
			2)
				DH_KEY_SIZE="3072"
				;;
			3)
				DH_KEY_SIZE="4096"
				;;
			esac
			;;
		esac
		echo ""
		# The "auth" options behaves differently with AEAD ciphers
		if [[ $CIPHER =~ CBC$ ]]; then
			echo "The digest algorithm authenticates data channel packets and tls-auth packets from the control channel."
		elif [[ $CIPHER =~ GCM$ ]]; then
			echo "The digest algorithm authenticates tls-auth packets from the control channel."
		fi
		echo "Which digest algorithm do you want to use for HMAC?"
		echo "   1) SHA-256 (recommended)"
		echo "   2) SHA-384"
		echo "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "Digest algorithm [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		echo ""
		echo "You can add an additional layer of security to the control channel with tls-auth and tls-crypt"
		echo "tls-auth authenticates the packets, while tls-crypt authenticate and encrypt them."
		echo "   1) tls-crypt (recommended)"
		echo "   2) tls-auth"
		until [[ $TLS_SIG =~ [1-2] ]]; do
			read -rp "Control channel additional security mechanism [1-2]: " -e -i 1 TLS_SIG
		done
	fi
	echo ""
	echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now."
	echo "You will be able to generate a client at the end of the installation."
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}

		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi
	fi

	# Run setup questions first, and set other variables if auto-install
	installQuestions

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Could not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# We add the OpenVPN repo to get the latest version.
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y oracle-epel-release-el8
			yum-config-manager --enable ol8_developer_EPEL
			yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'amzn2023' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi

	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.1.2"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki
		EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi

		EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi

	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi

	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem

	# Generate server.conf
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi

	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf

	# DNS resolvers
	case $DNS in
	1) # Current system resolvers
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	2) # Self-hosted DNS resolver (Unbound)
		echo 'push "dhcp-option DNS 10.8.0.1"' >>/etc/openvpn/server.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'push "dhcp-option DNS fd42:42:42:42::1"' >>/etc/openvpn/server.conf
		fi
		;;
	3) # Cloudflare
		echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		;;
	4) # Quad9
		echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		;;
	5) # Quad9 uncensored
		echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		;;
	6) # FDN
		echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		;;
	7) # DNS.WATCH
		echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		;;
	8) # OpenDNS
		echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		;;
	9) # Google
		echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		;;
	10) # Yandex Basic
		echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		;;
	11) # AdGuard DNS
		echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		;;
	12) # NextDNS
		echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
		echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		;;
	13) # Custom DNS
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf

	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi

	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi

	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf

	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn

	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' || $OS == 'amzn2023' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service

		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service

		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service

		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi

	if [[ $DNS == 2 ]]; then
		installUnbound
	fi

	# Add iptables rules in two scripts
	mkdir -p /etc/iptables

	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi

	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh

	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
	fi

	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh

	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt

	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi

	# Generate the custom client.ovpn
	newClient
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function newClient() {
	echo ""
	echo "Tell me a name for the client."
	echo "The name must consist of alphanumeric character. It may also include an underscore or a dash."

	until [[ $CLIENT =~ ^[a-zA-Z0-9_-]+$ ]]; do
		read -rp "Client name: " -e CLIENT
	done

	echo ""
	echo "Do you want to protect the configuration file with a password?"
	echo "(e.g. encrypt the private key with a password)"
	echo "   1) Add a passwordless client"
	echo "   2) Use a password for the client"

	until [[ $PASS =~ ^[1-2]$ ]]; do
		read -rp "Select an option [1-2]: " -e -i 1 PASS
	done

	CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E "/CN=$CLIENT\$")
	if [[ $CLIENTEXISTS == '1' ]]; then
		echo ""
		echo "The specified client CN was already found in easy-rsa, please choose another name."
		exit
	else
		cd /etc/openvpn/easy-rsa/ || return
		case $PASS in
		1)
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT" nopass
			;;
		2)
			echo "⚠️ You will be asked for the client password below ⚠️"
			EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-client-full "$CLIENT"
			;;
		esac
		echo "Client $CLIENT added."
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT}" ]; then
		# if $1 is a user name
		homeDir="/home/${CLIENT}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			homeDir="/root"
		else
			homeDir="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		homeDir="/root"
	fi

	# Determine if we use tls-auth or tls-crypt
	if grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		TLS_SIG="1"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		TLS_SIG="2"
	fi

	# Generates the custom client.ovpn
	cp /etc/openvpn/client-template.txt "$homeDir/$CLIENT.ovpn"
	{
		echo "<ca>"
		cat "/etc/openvpn/easy-rsa/pki/ca.crt"
		echo "</ca>"

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT.key"
		echo "</key>"

		case $TLS_SIG in
		1)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		2)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$homeDir/$CLIENT.ovpn"

	echo ""
	echo "The configuration file has been written to $homeDir/$CLIENT.ovpn."
	echo "Download the .ovpn file and import it in your OpenVPN client."

	exit 0
}

function revokeClient() {
	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client certificate you want to revoke"
	tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	until [[ $CLIENTNUMBER -ge 1 && $CLIENTNUMBER -le $NUMBEROFCLIENTS ]]; do
		if [[ $CLIENTNUMBER == '1' ]]; then
			read -rp "Select one client [1]: " CLIENTNUMBER
		else
			read -rp "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
		fi
	done
	CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
	cd /etc/openvpn/easy-rsa/ || return
	./easyrsa --batch revoke "$CLIENT"
	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
	rm -f /etc/openvpn/crl.pem
	cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	chmod 644 /etc/openvpn/crl.pem
	find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	rm -f "/root/$CLIENT.ovpn"
	sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt
	cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}

	echo ""
	echo "Certificate for client $CLIENT revoked."
}

function removeUnbound() {
	# Remove OpenVPN-related config
	sed -i '/include: \/etc\/unbound\/openvpn.conf/d' /etc/unbound/unbound.conf
	rm /etc/unbound/openvpn.conf

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		echo ""
		echo "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		# Stop Unbound
		systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y unbound
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y unbound
		fi

		rm -rf /etc/unbound/

		echo ""
		echo "Unbound removed!"
	else
		systemctl restart unbound
		echo ""
		echo "Unbound wasn't removed."
	fi
}

function removeOpenVPN() {
	echo ""
	read -rp "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN port from the configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)

		# Stop OpenVPN
		if [[ $OS =~ (fedora|arch|centos|oracle) ]]; then
			systemctl disable openvpn-server@server
			systemctl stop openvpn-server@server
			# Remove customised service
			rm /etc/systemd/system/openvpn-server@.service
		elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
			systemctl disable openvpn
			systemctl stop openvpn
		else
			systemctl disable openvpn@server
			systemctl stop openvpn@server
			# Remove customised service
			rm /etc/systemd/system/openvpn\@.service
		fi

		# Remove the iptables rules related to the script
		systemctl stop iptables-openvpn
		# Cleanup
		systemctl disable iptables-openvpn
		rm /etc/systemd/system/iptables-openvpn.service
		systemctl daemon-reload
		rm /etc/iptables/add-openvpn-rules.sh
		rm /etc/iptables/rm-openvpn-rules.sh

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					semanage port -d -t openvpn_port_t -p "$PROTOCOL" "$PORT"
				fi
			fi
		fi

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get remove --purge -y openvpn
			if [[ -e /etc/apt/sources.list.d/openvpn.list ]]; then
				rm /etc/apt/sources.list.d/openvpn.list
				apt-get update
			fi
		elif [[ $OS == 'arch' ]]; then
			pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			dnf remove -y openvpn
		fi

		# Cleanup
		find /home/ -maxdepth 2 -name "*.ovpn" -delete
		find /root/ -maxdepth 1 -name "*.ovpn" -delete
		rm -rf /etc/openvpn
		rm -rf /usr/share/doc/openvpn*
		rm -f /etc/sysctl.d/99-openvpn.conf
		rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/openvpn.conf ]]; then
			removeUnbound
		fi
		echo ""
		echo "OpenVPN removed!"
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to OpenVPN-install!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Revoke existing user"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done

	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}

# Check for root, TUN, OS...
initialCheck

# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi
}

setup_wireguard_vpn(){

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		echo "OpenVZ is not supported"
		exit 1
	}
	function lxcErr() {
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			apk update && apk add virt-what
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

function installQuestions() {
	echo "Welcome to the WireGuard installer!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "I need to ask you a few questions before starting the setup."
	echo "You can keep the default options and just press enter if you are ok with them."
	echo ""

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
	done

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "First DNS resolver to use for the clients: " -e -i 1.1.1.1 CLIENT_DNS_1
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		read -rp "Second DNS resolver to use for the clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
		read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	echo ""
	echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
	echo "You will be able to generate a client at the end of the installation."
	read -n1 -r -p "Press any key to continue..."
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		apk add wireguard-tools iptables libqrencode-tools
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
			echo ""
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
			echo ""
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			exit 1
		else
			echo "WireGuard uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function manageMenu() {
	echo "Welcome to WireGuard-install!"
	echo "The git repository is available at: https://github.com/angristan/wireguard-install"
	echo ""
	echo "It looks like WireGuard is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall WireGuard"
	echo "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi

}
reboot_system() {

	reboot now
	echo "The system will reboot"
}
shutdown_system() {

		shutdown now
		echo "The system will shutdown"

}
PXE_Setup () {


# ================================
# iVentoy PXE Installer & systemd
# ================================

# Colors for messages
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
NC="\e[0m" # No color

# Variables
IVENTOY_VERSION="1.0.19"
INSTALL_DIR="/opt/iventoy"
JSON_FILE="$INSTALL_DIR/iventoy.json"
SERVICE_FILE="/etc/systemd/system/iventoy.service"
DOWNLOAD_URL="https://github.com/ventoy/PXE/releases/download/v$IVENTOY_VERSION/iventoy-$IVENTOY_VERSION-linux-free.tar.gz"

echo -e "${BLUE}🚀 Starting iVentoy PXE installation...${NC}"

# ------------------------------
# 1️⃣ Stop and clean previous installation and configuration files
# ------------------------------
echo -e "${YELLOW}🔄 Stopping and removing previous configurations...${NC}"

if systemctl is-active --quiet iventoy.service; then
    echo -e "${YELLOW}Stopping existing service...${NC}"
    sudo systemctl stop iventoy.service
fi

if systemctl list-unit-files | grep -q iventoy.service; then
    echo -e "${YELLOW}Disabling existing service...${NC}"
    sudo systemctl disable iventoy.service
fi

if [ -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Removing old service file...${NC}"
    sudo rm -f "$SERVICE_FILE"
fi

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Removing previous installation and configuration files...${NC}"
    sudo rm -rf "$INSTALL_DIR"
fi

# ------------------------------
# 2️⃣ Create installation directory
# ------------------------------
echo -e "${BLUE}📂 Creating installation directory: $INSTALL_DIR${NC}"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

# ------------------------------
# 3️⃣ Download and extract iVentoy
# ------------------------------
echo -e "${BLUE}⬇️  Downloading iVentoy version $IVENTOY_VERSION...${NC}"
wget $DOWNLOAD_URL -O /tmp/iventoy.tar.gz

echo -e "${BLUE}📦 Extracting files into $INSTALL_DIR...${NC}"
tar -xzf /tmp/iventoy.tar.gz -C $INSTALL_DIR

# ------------------------------
# 4️⃣ Detect iventoy.sh
# ------------------------------
SCRIPT_PATH=$(find $INSTALL_DIR -name iventoy.sh | head -n1)
if [ -z "$SCRIPT_PATH" ]; then
    echo -e "${RED}❌ Error: iventoy.sh was not found after extracting the tar.${NC}"
    exit 1
fi
chmod +x "$SCRIPT_PATH"
echo -e "${GREEN}✔ Found iventoy.sh at: $SCRIPT_PATH${NC}"

# ------------------------------
# 5️⃣ Create JSON file
# ------------------------------
echo -e "${BLUE}📝 Creating JSON file with executable path...${NC}"
cat <<EOF > $JSON_FILE
{
  "path": "$SCRIPT_PATH"
}
EOF
echo -e "${GREEN}✔ JSON created at $JSON_FILE${NC}"

# ------------------------------
# 6️⃣ Create systemd service
# ------------------------------
echo -e "${BLUE}⚙️  Configuring systemd service...${NC}"
sudo bash -c "cat <<EOF > $SERVICE_FILE
[Unit]
Description=iVentoy PXE Service
After=network.target

[Service]
Type=forking
ExecStart=/bin/bash $SCRIPT_PATH start
ExecStop=/bin/bash $SCRIPT_PATH stop
Restart=on-failure
WorkingDirectory=$(dirname $SCRIPT_PATH)
User=root

[Install]
WantedBy=multi-user.target
EOF"

# ------------------------------
# 7️⃣ Enable and start service
# ------------------------------
echo -e "${BLUE}🚀 Enabling and starting the service...${NC}"
sudo systemctl daemon-reload
sudo systemctl enable iventoy.service
sudo systemctl restart iventoy.service

# ------------------------------
# 8️⃣ Quick verification
# ------------------------------
echo -e "${GREEN}🎉 iVentoy successfully installed in $INSTALL_DIR${NC}"
echo -e "${GREEN}📄 JSON created at $JSON_FILE${NC}"
echo -e "${GREEN}🔹 Systemd service active: systemctl status iventoy.service${NC}"
echo -e "${GREEN}🔹 iVentoy will start automatically at boot${NC}"
echo -e "${GREEN}🔹 To access the PXE Web UI, go to http://x.x.x.x:26000 or localhost:26000${NC}"

}


# Main Menu
while true; do

    echo "==================================================================="
    echo "========================= ZenNet Forge ============================"
    echo "==================================================================="
    echo "==================== by: Jaime Galvez Martinez ===================="
    echo "=================== GitHub: JaimeGalvezMartinez ==================="
    echo "==================================================================="
    echo ""
    echo "1) Configure network interfaces"
    echo "2) Configure gateway server"
    echo "3) Configure DHCP server"
    echo "4) Install forwarder + cache DNS "
    echo "5) Configur Local DNS Server"
    echo "6) Configure SAMBA server"
    echo "7) Configure FTP server over SSH"
    echo "8) Configure Firewall"
    echo "9) Install Nextcloud latest version"
    echo "10) Install Moodle Latest Version"
    echo "11) Install Wordpress"
    echo "12) VirtualHost Setup"
    echo "13) Network Scan"
    echo "14) Install & Configure Prometheus "
    echo "15) Install Graphana "
    echo "16) Show system Informaton "
    echo "17) Configure ACL "
    echo "18) Cerbot Management "
    echo "19) Make Backup or restore backup from ssh server "
    echo "20) Setup OpenVPN"
    echo "21) Setup Wireguard VPN"
    echo "22) Install Preboot eXecution Environment (PXE) "
	echo "23) Install Zentyal on Ubuntu 18.04 or Ubuntu 20.04"
	echo "24) Install Zentyal on Ubuntu 22.04 or lastest"
	echo "25) Reboot System "
	echo "26) Shutdown System "
	echo "27) Exit "
    read -p "Choose an option: " opcion

    # case for execute the fuctions
    case $opcion in
    1) configure_network ;;
    2) configure_gateway_server ;;
    3) configure_dhcp_server ;;
	4) install_forwarder_dns ;;
    5) configure_local_dns_server ;;
    6) install_samba_server ;;
    7) install_ftp_server_over_ssh ;;
    8) configure_firewall ;;
    9) nextcloud_install ;;
    10) moodle_install ;;
	11) wp_install ;;
 	12) setup_virtualhost ;;
    13) network_scan ;;
	14) configure_prometheus ;;
 	15) configure_graphana ;;
  	16) show_system_info ;;
   	17) configure_acl ;;
    18) manage_certbot ;;
	19) backup_or_restore_backup_from_ssh_server ;;
 	20) setup_open_vpn;;
  	21) setup_wireguard_vpn;;
	22) PXE_Setup;;
	23) zentyal_70_setup;;
	24) zentyal_80_setup;;
	25) reboot_system ;;
	26) shutdown_system ;;
    27) echo "Exiting. Goodbye!"; break ;;
        *) echo "Invalid option." ;;
    esac
done
