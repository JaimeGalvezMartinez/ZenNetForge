
 
#!/bin/bash
# Version 1.4 - Febrary 2024
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

configure_network() {


    echo "--------------------------------------"
    echo "Network interfaces in your system:"
    echo "--------------------------------------"
    INTERFACES=$(ip link show | awk -F': ' '{print $1,  $2}')
    echo "$INTERFACES"
    echo "======================================"
    read -p "Input the name of the interface to configure: " SELECTED_INTERFACE
    if ! echo "$INTERFACES" | grep -qw "$SELECTED_INTERFACE"; then
        echo "Invalid Interface. Exit......."
        exit 1
    fi
    echo "Selected Interface: $SELECTED_INTERFACE"
    echo "1) Configure static IP"
    echo "2) Configure via DHCP"
    echo "3) Configure DNS"
    echo "4) Exit"
    read -p "Choose an option: " OPTION
    case $OPTION in
        1)  # IP estática
            read -p "Enter IP Address: (example: 192.168.1.100)" IP
            read -p "Enter the Netmask (CIDR format)(example 24 for 255.255.255.0): " MASCARA
            read -p "Enter the IP of Gateway/Router (example 192.168.1.1): " GATEWAY
            sudo ip addr flush dev $SELECTED_INTERFACE
            sudo ip addr add $IP/$MASCARA dev $SELECTED_INTERFACE
            sudo ip route add default via $GATEWAY
            echo "Static IP configured on $SELECTED_INTERFACE."
            ;;
        2)  # DHCP
            sudo dhclient -r $SELECTED_INTERFACE
            sudo dhclient $SELECTED_INTERFACE
            echo "Interface $SELECTED_INTERFACE configured via DHCP."
            ;;
        3)  # DNS
            read -p "Primary DNS: " DNS1
            read -p "Secondary DNS (optional): " DNS2
            sudo cp /etc/resolv.conf /etc/resolv.conf.bak
            echo "nameserver $DNS1" | sudo tee /etc/resolv.conf > /dev/null
            [[ -n "$DNS2" ]] && echo "nameserver $DNS2" | sudo tee -a /etc/resolv.conf > /dev/null
            echo "DNS updated."
            ;;
        4)  echo "Exiting." ;;
        *)  echo "Invalid Option." ;;
    esac
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

install_sftp_server() {

# Upgrade system and packages
echo "Upgrading System..."
apt update && apt upgrade -y

# Install OpenSSH (which includes the SFTP server)
echo "Installing OpenSSH..."
apt install openssh-server -y

# Enable and start the SSH service
echo "Enabling and starting the SSH service..."
systemctl enable ssh
systemctl start ssh

# Ask the user to choose a username for SFTP access
read -p "Input the username for access to the SFTP: " username
# Create a system user
sudo useradd "$username"
sudo passwd "$username"

# Create a directory for the SFTP user (e.g., /home/username/sftp)
mkdir -p /home/"$username"/sftp
chown root:root /home/"$username"
chmod 755 /home/"$username"

# Set permissions for the SFTP directory for the user
mkdir -p /home/"$username"/sftp/uploads
chown "$username":"$username" /home/"$username"/sftp/uploads
chmod 700 /home/"$username"/sftp/uploads

# Configure the SSH config file to restrict access to SFTP only
echo "Configuring SSH..."
echo "
# SFTP configuration for user $username
Match User $username
    ForceCommand internal-sftp
    PasswordAuthentication yes
    ChrootDirectory /home/$username
    AllowTcpForwarding no
    X11Forwarding no
" >> /etc/ssh/sshd_config

# Restart the SSH service to apply changes
systemctl restart ssh

# Verify if the SSH service is active
if systemctl is-active --quiet ssh; then
    echo "SFTP server is running correctly."
else
    echo "There was a problem starting the SSH server."
    exit 1
fi
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
setup_virtualhost () {

#!/bin/bash

# Ask user for domain name
read -p "Enter your domain name: " DOMAIN

# Ask user for document root
read -p "Enter your document root (default: /var/www/html/$DOMAIN): " DOC_ROOT
DOC_ROOT=${DOC_ROOT:-/var/www/html/$DOMAIN}

# Ask user if they want SSL
read -p "Do you want to enable SSL? (y/n): " ENABLE_SSL
CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN.conf
SSL_CONFIG_FILE=/etc/apache2/sites-available/$DOMAIN-ssl.conf

# Create document root
sudo mkdir -p $DOC_ROOT
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
        2) echo "Exiting..."; exit 0 ;;
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
    echo "4) Change FQDN Name"
    echo "5) Configure SAMBA server"
    echo "6) Configure SFTP server"
    echo "7) Configure Firewall"
    echo "8) Install Nextcloud latest version"
    echo "9) Install Moodle Latest Version"
    echo "10) Install Wordpress"
    echo "11) VirtualHost Setup
    echo "12) Network Scan"
    echo "13) Exit"
    read -p "Choose an option: " opcion

    case $opcion in
        1) configure_network ;;
        2) configure_gateway_server ;;
        3) configure_dhcp_server ;;
        4) configure_fqdn_name ;;
        5) install_samba_server ;;
        6) install_sftp_server ;;
        7) configure_firewall ;;
        8) nextcloud_install ;;
        9) moodle_install ;;
	10) wp_install ;;
 	11) setup_virtualhost ;;
        12) network_scan ;;
        13) echo "Exiting. Goodbye!"; break ;;
        *) echo "Invalid option." ;;
    esac
done
