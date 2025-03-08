
 
#!/bin/bash
# Version 1.7 - March 2025
# Developer: Jaime Galvez (TheHellishPandaa)
# Description: Bash script for configuring gateway server, DHCP, SAMBA, OpenSSH, etc.
# This Script is released under GNU General public license.
# If you like my work, please support it with a start in my github´s profile

clear

# Check if exec in superuser permissions. 
if [ $EUID -ne 0 ]; then
   echo "This script must be run with superuser permissions (sudo)"
   exit 1
fi

configure_firewall() {


    echo "==============================================================================="
    echo "=========================== Firewall SETUP ===================================="
    echo "==============================================================================="

    # Asegurarse de que UFW está instalado
    if ! command -v ufw &>/dev/null; then
        echo "UFW no está instalado. Install UFW (Uncomplicated Firewall)..."
        apt update && apt install ufw -y
    fi

    # Verificar si UFW está activo
    if sudo ufw status | grep -q "inactive"; then
        echo "Activating UFW..."
        sudo ufw enable
    else
        echo "UFW is already active."
    fi

    while true; do
        echo "Select an option to configure the firewall:"
        echo "1) Allow access to a specific port"
        echo "2) Allow access to a specific port via specific IP"
        echo "3) Show firewall rules"
        echo "4) Install Firewall"
        echo "5) Activate Firewall"
        echo "6) Disable Firewall"
        echo "7) Exit"
        read -p "Choose an option: " opcion

        case $opcion in
            1)  # Permitir acceso a un puerto específico
                read -p "Input the port to allow (e.g., 80, 443, 22): " puerto
                echo "Allowing access to port $puerto..."
                sudo ufw allow "$puerto"
                echo "Port $puerto allowed."
                ;;
            2)  # Permitir acceso a un puerto específico desde una IP
                read -p "Input the port to allow (e.g., 80, 443, 22): " puerto
                read -p "Input the IP (e.g., 192.168.1.100): " ip
                echo "Allowing access to port $puerto from IP $ip..."
                sudo ufw allow from "$ip" to any port "$puerto"
                echo "Access to port $puerto from IP $ip allowed."
                ;;
            3)  # Ver reglas actuales
                echo "Showing current firewall rules..."
                sudo ufw status verbose
                ;;
            4)  # Install UFW
                echo "Installing UFW..."
                sudo apt update -y
                sudo apt install ufw -y
                ;;
            5)  # Activate firewall
                echo "Activating firewall..."
                sudo ufw enable
                ;;
            6)  # Disable Firewall
                echo "Disabling firewall..."
                sudo ufw disable
                ;;
            7)  # Salir
                echo "Exiting firewall configuration."
                break
                ;;
            *)  # Opción no válida
                echo "Invalid option."
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
        8.8.8.8;  // Google DNS
        8.8.4.4;  // Google Secondary DNS
        1.1.1.1;  // Cloudflare DNS
        1.0.0.1;  // Cloudflare Secondary DNS
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
    ip -o link show | awk -F': ' '!/ lo:/{print $2}' | while read -r interface; do
        mac=$(cat /sys/class/net/$interface/address)
        echo "Interface: $interface - MAC: $mac"
    done

    echo "--------------------------------"

    # Ask the user to select an interface
    read -p "Enter the network interface you want to configure: " interface

    # Ask if they want a static IP or DHCP
    echo "Do you want to configure a Static IP or use DHCP?"
    echo "1) Static IP"
    echo "2) DHCP (Automatic)"
    read -p "Select an option (1 or 2): " option

    # Initialize variables
    dns_servers=""
    gateway=""

    if [[ "$option" == "1" ]]; then
        # Static IP Configuration
        read -p "Enter the IP address (e.g., 192.168.1.100): " ip_address
        read -p "Enter the CIDR prefix (e.g., 24 for 255.255.255.0): " cidr
        read -p "Enter the gateway (or press Enter to skip): " gateway

        # Ask if the user wants to configure custom DNS servers
        read -p "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -p "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        # Validate CIDR prefix
        if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 1 ] || [ "$cidr" -gt 32 ]; then
            echo "Error: CIDR prefix must be a number between 1 and 32."
            exit 1
        fi

        # Create Netplan configuration for Static IP
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

        # Add gateway if provided
        if [[ -n "$gateway" ]]; then
            sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      gateway4: $gateway
EOF
        fi

        # Add DNS configuration if the user provided DNS servers
        if [[ -n "$dns_servers" ]]; then
            sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
        fi

    elif [[ "$option" == "2" ]]; then
        # Ask if the user wants to configure custom DNS servers
        read -p "Do you want to configure custom DNS servers? (y/n): " configure_dns
        if [[ "$configure_dns" =~ ^[Yy]$ ]]; then
            read -p "Enter DNS servers (comma-separated, e.g., 8.8.8.8,8.8.4.4): " dns_servers
        fi

        # Create Netplan configuration for DHCP
        sudo tee /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $interface:
      dhcp4: yes
EOF

        # Add DNS configuration if the user provided DNS servers
        if [[ -n "$dns_servers" ]]; then
            sudo tee -a /etc/netplan/01-netcfg.yaml > /dev/null <<EOF
      nameservers:
        addresses: [$dns_servers]
EOF
        fi

    else
        echo "Invalid option. You must choose 1 or 2."
        exit 1
    fi

    # Adjust Netplan file permissions to avoid warnings
    sudo chmod 600 /etc/netplan/01-netcfg.yaml

    # Apply Netplan configuration
    sudo netplan apply

    echo "Network configuration successfully applied. 🚀"
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

  # Configure the dhcpd.conf file with basic settings
  configure_dhcp

  # Restart and enable the DHCP service
  systemctl restart isc-dhcp-server
  systemctl enable isc-dhcp-server

  echo "DHCP server configured on interface $interface_name with network 10.33.206.0/24."

# Function to configure the dhcpd.conf file
configure_dhcp() {
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
}
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

# Change FQDN Name
configure_fqdn_name() {


    read -p "New FQDN (e.g., server.example.com): " NEW_FQDN
    NEW_HOSTNAME=$(echo $NEW_FQDN | cut -d '.' -f 1)
    echo $NEW_HOSTNAME > /etc/hostname
    echo "127.0.1.1 $NEW_FQDN $NEW_HOSTNAME" >> /etc/hosts

    hostnamectl set-hostname $NEW_HOSTNAME
    echo "================================================"
    echo "          FQDN updated to $NEW_FQDN             "
    echo "================================================"
    echo ""
    echo ""
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
echo "                   Nextcloud Installation                  "
echo "==========================================================="
echo ""
echo ""

# Check if the user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." 
    exit 1
fi


# Interactive Nextcloud Installation Script

read -p "Enter the database user name (default: root): " DB_USER
DB_USER=${DB_USER:-"root"}


# Prompt for database name
read -p "Enter the database name (default: nextcloud_db): " DB_NAME
DB_NAME=${DB_NAME:-"nextcloud_db"}



# Prompt for database password
read -sp "Enter the password for the database user: " DB_PASSWORD
echo

# Prompt for Nextcloud installation path
read -p "Enter the Nextcloud installation path (default: /var/www/html/nextcloud): " NEXTCLOUD_PATH
NEXTCLOUD_PATH=${NEXTCLOUD_PATH:-"/var/www/html/nextcloud"}

read -p "What will be your data directory? (default: /var/www/nextcloud/data): " data_directory
data_directory=${data_directory:-"/var/www/nextcloud/data"}

# Prompt for domain or IP
read -p "Enter the domain or IP to access Nextcloud: " DOMAIN

# Confirm the configuration
echo -e "\n========================================================"
echo -e "============ Configuration Summary: ===================="
echo -e "========================================================\n"
echo "Database: $DB_NAME"
echo "Database User: $DB_USER"
echo "Installation Path: $NEXTCLOUD_PATH"
echo "Domain or IP: $DOMAIN"
read -p "Do you want to proceed with the installation? (y/n): " CONFIRM
echo
if [[ "$CONFIRM" != [yY] ]]; then
    echo "Installation canceled."
    exit 1
fi

# Update system packages
echo "Updating system..."
apt update && apt upgrade -y

# Install required software
echo "Installing Apache, MariaDB, PHP, and required dependencies..."
apt install -y apache2 mariadb-server php php-cli php-fpm php-gd php-json php-mbstring php-curl php-xml php-zip php-mysql php-intl php-bz2 php-imagick libapache2-mod-php unzip wget

sudo apt update
sudo apt install lbzip2 -y

# Configure MariaDB
echo "Configuring MariaDB..."
mysql_secure_installation
mysql -u root -e "CREATE DATABASE ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Configure PHP
echo "Configuring PHP..."
PHP_INI_PATH=$(php -r "echo php_ini_loaded_file();")
sed -i "s/memory_limit = .*/memory_limit = 512M/" "$PHP_INI_PATH"
sed -i "s/upload_max_filesize = .*/upload_max_filesize = 512M/" "$PHP_INI_PATH"
sed -i "s/post_max_size = .*/post_max_size = 512M/" "$PHP_INI_PATH"
sed -i "s/max_execution_time = .*/max_execution_time = 300/" "$PHP_INI_PATH"

# Download and configure Nextcloud
echo "Downloading the latest version of Nextcloud..."
wget https://download.nextcloud.com/server/releases/latest.tar.bz2 -O nextcloud.tar.bz2
tar -xf nextcloud.tar.bz2
mv nextcloud $NEXTCLOUD_PATH
chown -R www-data:www-data $NEXTCLOUD_PATH
chmod -R 770 $NEXTCLOUD_PATH

# Configure Apache for Nextcloud

systemctl restart apache2

#Configure Data Directory
mkdir $data_directory
chown -R www-data:www-data $data_directory
chmod -R 755 $data_directory

# Finish
echo "Nextcloud installation complete."
echo "Please access http://$DOMAIN to complete setup in the browser."

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



# Prompt for database password
read -sp "Enter the password for the database user: " DB_PASSWORD
echo

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


# Download and configure Nextcloud
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
read -s -p "Enter the database password: " DB_PASS
echo ""

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
}

install_node_exporter() {
    echo "Downloading Node Exporter v$NODE_EXPORTER_VERSION..."
    wget https://github.com/prometheus/node_exporter/releases/download/v$NODE_EXPORTER_VERSION/node_exporter-$NODE_EXPORTER_VERSION.linux-amd64.tar.gz -O /tmp/node_exporter.tar.gz
    
    echo "Extracting Node Exporter..."
    tar -xzf /tmp/node_exporter.tar.gz -C /tmp/
    mv /tmp/node_exporter-$NODE_EXPORTER_VERSION.linux-amd64/node_exporter $PROM_BIN_DIR/
    chown $PROM_USER:$PROM_USER $PROM_BIN_DIR/node_exporter
    echo "Node Exporter binary installed in: $PROM_BIN_DIR"
    
    echo "Creating Node Exporter systemd service..."
    cat <<EOF > /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=$PROM_USER
Group=$PROM_USER
Type=simple
ExecStart=$PROM_BIN_DIR/node_exporter

[Install]
WantedBy=multi-user.target
EOF
    
    echo "Node Exporter systemd service file created at: /etc/systemd/system/node_exporter.service"
    
    systemctl daemon-reload
    systemctl enable --now node_exporter.service
    echo "Node Exporter installation complete! Running on port 9100"
}

add_node_exporter_to_prometheus() {
    read -p "Enter the IP address of the Node Exporter: " NODE_EXPORTER_IP
    echo "Adding Node Exporter job to prometheus.yml..."
    cat <<EOF >> $PROM_DIR/prometheus.yml

  - job_name: 'node_exporter'
    static_configs:
      - targets: ['$NODE_EXPORTER_IP:9100']
EOF
    echo "Node Exporter added to Prometheus configuration. Restarting Prometheus..."
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
echo "Grafana has been successfully installed on the server!"
echo "You can access the Grafana web interface at http://<YOUR-SERVER-IP>:3000."
echo "Default username: admin"
echo "Default password: admin"

# Warning message for first login
echo "Remember to change the password on the first login."
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


# Main Menu
while true; do

    echo "==================================================================="
    echo "========================= ZenNet Forge ============================"
    echo "==================================================================="
    echo "====================== by: TheHellishPandaa ======================="
    echo "==================== GitHub: TheHellishPandaa ====================="
    echo "==================================================================="
    echo ""
    echo "1) Configure network interfaces"
    echo "2) Configure gateway server"
    echo "3) Configure DHCP server"
    echo "4) Install forwarder + cache DNS "
    echo "5) Change FQDN Name"
    echo "6) Configure SAMBA server"
    echo "7) Configure FTP server over SSH"
    echo "8) Configure Firewall"
    echo "9) Install Nextcloud latest version"
    echo "10) Install Moodle Latest Version"
    echo "11) Install Wordpress"
    echo "12) VirtualHost Setup"
    echo "13) Network Scan"
    echo "14) Install Prometheus "
    echo "15) Install Graphana "
    echo "16) Exit"
    read -p "Choose an option: " opcion

    case $opcion in
        1) configure_network ;;
        2) configure_gateway_server ;;
        3) configure_dhcp_server ;;
	4) install_forwarder_dns ;;
        5) configure_fqdn_name ;;
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
        16) echo "Exiting. Goodbye!"; break ;;
        *) echo "Invalid option." ;;
    esac
done
