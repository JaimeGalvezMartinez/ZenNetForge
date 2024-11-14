#!/bin/bash
#version 1.1
#Date: November 2024
#Developer: Jaime Galvez (TheHellishPandaa)
#Description: Bash-script based of Zentyal Server, script that install gateway, DHCP Server, SAMBA, OpenSSH etc...

clear
# Comprobamos si el usuario tiene permisos de superusuario
if [[ $EUID -ne 0 ]]; then
   echo "Este script debe ejecutarse con permisos de superusuario (sudo)"
   exit 1
fi
configurar_firewall() {
    echo "==================================================================="
    echo "=========================== Configuración del Firewall ==========="
    echo "==================================================================="

    # Asegurarse de que UFW está instalado
    if ! command -v ufw &>/dev/null; then
        echo "UFW no está instalado. Instalando..."
        apt update && apt install ufw -y
    fi

    # Verificar si UFW está activo
    if sudo ufw status | grep -q "inactive"; then
        echo "Activando UFW..."
        sudo ufw enable
    else
        echo "UFW ya está activo."
    fi

    while true; do
        echo "Selecciona una opción para configurar el firewall:"
        echo "1) Permitir acceso a un puerto específico"
        echo "2) Permitir acceso a un puerto específico desde una IP"
        echo "3) Ver reglas actuales del firewall"
        echo "4) Salir"
        read -p "Selecciona una opción: " opcion

        case $opcion in
            1)  # Permitir acceso a un puerto específico
                read -p "Introduce el puerto que deseas permitir (por ejemplo, 80, 443, 22): " puerto
                echo "Permitiendo acceso al puerto $puerto..."
                sudo ufw allow $puerto
                echo "Puerto $puerto permitido."
                ;;
            2)  # Permitir acceso a un puerto específico desde una IP
                read -p "Introduce el puerto que deseas permitir (por ejemplo, 80, 443, 22): " puerto
                read -p "Introduce la dirección IP desde la cual deseas permitir el acceso (por ejemplo, 192.168.1.100): " ip
                echo "Permitiendo acceso al puerto $puerto desde la IP $ip..."
                sudo ufw allow from $ip to any port $puerto
                echo "Acceso al puerto $puerto desde la IP $ip permitido."
                ;;
            3)  # Ver reglas actuales
                echo "Mostrando las reglas actuales del firewall..."
                sudo ufw status verbose
                ;;
            4)  # Salir
                echo "Saliendo de la configuración del firewall."
                break
                ;;
            *)  # Opción no válida
                echo "Opción no válida, por favor intenta de nuevo."
                ;;
        esac
    done
}

instalar_servidor_sftp() {

# Actualiza el sistema y los paquetes
echo "Actualizando el sistema..."
apt update && apt upgrade -y

# Instalar OpenSSH (que incluye el servidor SFTP)
echo "Instalando OpenSSH..."
apt install openssh-server -y

# Habilitar y iniciar el servicio SSH
echo "Habilitando e iniciando el servicio SSH..."
systemctl enable ssh
systemctl start ssh

# Pide al usuario que elija el nombre de usuario para el acceso SFTP
read -p "Introduce el nombre de usuario para el acceso SFTP: " usuario
# Crear un usuario del sistema)
sudo useradd "$usuario"
sudo passwd $usuario
# Crea un directorio para el usuario SFTP (por ejemplo, /home/usuario/sftp)
mkdir -p /home/"$usuario"/sftp
chown root:root /home/"$usuario"
chmod 755 /home/"$usuario"

# Establecer permisos en el directorio de SFTP para el usuario
mkdir -p /home/"$usuario"/sftp/uploads
chown "$usuario":"$usuario" /home/"$usuario"/sftp/uploads
chmod 700 /home/"$usuario"/sftp/uploads

# Configura el archivo de configuración SSH para restringir el acceso solo a SFTP
echo "Configurando SSH para habilitar solo SFTP..."
echo "
# Configuración de SFTP para el usuario $usuario
Match User $usuario
    ForceCommand internal-sftp
    PasswordAuthentication yes
    ChrootDirectory /home/$usuario
    AllowTcpForwarding no
    X11Forwarding no
" >> /etc/ssh/sshd_config

# Reiniciar el servicio SSH para aplicar cambios
systemctl restart ssh

# Verificar si el servicio SSH está activo
if systemctl is-active --quiet ssh; then
    echo "El servidor SFTP está funcionando correctamente."
else
    echo "Hubo un problema al iniciar el servidor SSH."
    exit 1
fi

# Mostrar detalles de la configuración
echo "El servidor SFTP ha sido configurado correctamente."
echo "El usuario '$usuario' puede acceder a través de SFTP con la carpeta: /home/$usuario/sftp/uploads"
echo ""
echo "=============================================================================================="
echo "Puedes usar FileZilla como cliente SFTP para acceder al servidor"
echo "=============================================================================================="
echo ""
}


configurar_red() {
    # Preguntar al usuario por la interfaz de red a configurar
    ip a
    echo "=========================================================================="
    echo ""
    read -p "Introduce el nombre de la interfaz de red a configurar (por ejemplo, eth0 o enp3s0): " interfaz

    # Comprobar si la interfaz existe
    if ! ip link show "$interfaz" &> /dev/null; then
        echo "Error: La interfaz $interfaz no existe."
        return 1
    fi

    # Solicitar al usuario los parámetros de red
    read -p "Introduce la dirección IP (por ejemplo, 192.168.1.10): " ip
    read -p "Introduce la máscara de red (por ejemplo, 255.255.255.0 o 255.255.0.0): " mascara
    read -p "Introduce la puerta de enlace (por ejemplo, 192.168.1.1): " gateway
    read -p "Introduce la dirección DNS (por ejemplo, 8.8.8.8): " dns

    # Configurar la IP y la máscara de red en la interfaz
    sudo ip addr flush dev "$interfaz"  # Limpiar configuraciones previas
    sudo ip addr add "$ip/$mascara" dev "$interfaz"
    sudo ip link set "$interfaz" up

    # Configurar la puerta de enlace
    sudo ip route add default via "$gateway" dev "$interfaz"

    # Configurar el DNS (usando nmcli, si NetworkManager está instalado)
    if command -v nmcli &> /dev/null; then
        sudo nmcli dev set "$interfaz" managed yes
        sudo nmcli con mod "$interfaz" ipv4.dns "$dns"
        sudo nmcli con up "$interfaz"
    else
        # Alternativa: escribir directamente en resolv.conf si no se tiene nmcli
        echo "nameserver $dns" | sudo tee /etc/resolv.conf > /dev/null
    fi

    echo "Configuración de red completada en la interfaz $interfaz"
}

function configurar_gateway() {
    echo "Configurando gateway..."
        ip a
    echo "======================================================================================="
    echo ""
    read -p "Ingrese la interfaz que tiene acesso a Internet:" WAN_INTERFACE
    read -p "Ingrese la interfaz LAN:" LAN_INTERFACE
# Network Interface Variables

# Check if the interfaces exist
if ! ip a show $WAN_INTERFACE &>/dev/null; then
  echo "Error: WAN interface ($WAN_INTERFACE) does not exist."
  exit 0
fi

if ! ip a show $LAN_INTERFACE &>/dev/null; then
  echo "Error: LAN interface ($LAN_INTERFACE) does not exist."
  exit 0
fi

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

echo "Router successfully configured on $WAN_INTERFACE and $LAN_INTERFACE."
    echo "Gateway configurado correctamente."
}

function configurar_servidor_dhcp() {
    echo "================================="
    echo ""
    echo "Configurando servidor DHCP..."
    echo ""
    echo "1) Asignar una IP a una MAC"
    echo "2) Bloquear una IP"
    echo "3) Cambiar configuración de la red"
    echo "4) Instalar Servidor DHCP"
    read -p "Selecciona una opción: " dhcp_option
    case $dhcp_option in
        1)
            read -p "Ingresa la dirección MAC del dispositivo: " mac
            read -p "Ingresa la dirección IP a asignar: " ip
            echo "host dispositivo_$mac {
                hardware ethernet $mac;
                fixed-address $ip;
            }" >> /etc/dhcp/dhcpd.conf
            echo "Asignación de IP configurada para la MAC $mac."
            ;;
        2)
            read -p "Ingresa la dirección IP a bloquear: " ip_bloqueada
            echo "deny $ip_bloqueada;" >> /etc/dhcp/dhcpd.conf
            echo "IP $ip_bloqueada bloqueada en el servidor DHCP."
            ;;
        3)
            echo "Cambiando configuración de red para el servidor DHCP..."
            read -p "Ingresa la red (ej: 192.168.1.0): " network
            read -p "Ingresa la máscara de subred (ej: 255.255.255.0): " netmask
            read -p "Ingresa el rango de IPs para asignar (ej: 192.168.1.100 192.168.1.200): " range
            echo "
	4)
subnet $network netmask $netmask {
    range $range;
    option routers $gateway;
}" >> /etc/dhcp/dhcpd.conf
            echo "Configuración de red actualizada en el servidor DHCP."
            ;;
        *)
            echo "Opción no válida."
            ;;
    esac
    systemctl restart isc-dhcp-server
    echo "Servidor DHCP configurado y reiniciado."
}

function configurar_servidor_dns() {
    echo "Configurando servidor DNS local..."
     echo "Instalando servidor DNS"
     apt install bind9

    # Solicitar el dominio y la IP
    read -p "Ingresa el dominio a resolver (ej: ejemplo.com): " domain
    read -p "Ingresa la dirección IP del dominio: " ip

    # Archivo de configuración de la zona
    zone_file="/etc/bind/db.$domain"
    
    # Configurar la zona en named.conf.local
    echo "Añadiendo configuración de la zona en /etc/bind/named.conf.local..."
    echo "zone \"$domain\" {" >> /etc/bind/named.conf.local
    echo "    type master;" >> /etc/bind/named.conf.local
    echo "    file \"$zone_file\";" >> /etc/bind/named.conf.local
    echo "};" >> /etc/bind/named.conf.local

    # Crear archivo de zona
    echo "Creando archivo de zona en $zone_file..."
    cat <<EOL > $zone_file
\$TTL    604800
@       IN      SOA     ns.$domain. root.$domain. (
                          2         ; Serial
                     604800         ; Refresh
                      86400         ; Retry
                    2419200         ; Expire
                     604800 )       ; Negative Cache TTL
;
@       IN      NS      ns.$domain.
ns      IN      A       127.0.0.1
@       IN      A       $ip
EOL

    # Reiniciar el servicio de Bind
    echo "Reiniciando el servicio Bind9..."

    systemctl restart bind9

    echo "Servidor DNS configurado y reiniciado para el dominio $domain con IP $ip."
}
nextcloud22.0.0_install() {
   echo ""
   echo "======================================================================================="
   echo ""

read -p "Which version of Nextcloud would you like to install? (Default: 22.0.0): " NEXTCLOUD_VERSION
NEXTCLOUD_VERSION=${NEXTCLOUD_VERSION:-"22.0.0"}  # Default version if user inputs nothing

# Prompt for database name
read -p "Enter the database name (default: nextcloud_db): " DB_NAME
DB_NAME=${DB_NAME:-"nextcloud_db"}

# Prompt for database user
read -p "Enter the database user name (default: nextcloud_user): " DB_USER
DB_USER=${DB_USER:-"nextcloud_user"}

# Prompt for database password
read -sp "Enter the password for the database user: " DB_PASSWORD
echo

# Prompt for Nextcloud installation path
read -p "Enter the Nextcloud installation path (default: /var/www/html/nextcloud): " NEXTCLOUD_PATH
NEXTCLOUD_PATH=${NEXTCLOUD_PATH:-"/var/www/html/nextcloud"}

# Prompt for domain or IP
read -p "Enter the domain or IP to access Nextcloud: " DOMAIN

# Configuration confirmation
echo -e ""
echo -e "========================================================"
echo -e "============ Configuration Summary: ===================="
echo -e "========================================================"
echo -e ""

echo "Nextcloud Version: $NEXTCLOUD_VERSION"
echo "Database: $DB_NAME"
echo "Database User: $DB_USER"
echo "Installation Path: $NEXTCLOUD_PATH"
echo "Domain or IP: $DOMAIN"
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
mysql_secure_installation

# Create database and user for Nextcloud
echo "Configuring database for Nextcloud..."
mysql -u root -e "CREATE DATABASE ${DB_NAME};"
mysql -u root -e "CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -u root -e "GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';"
mysql -u root -e "FLUSH PRIVILEGES;"

# Install PHP and necessary modules
echo "Installing PHP  and modules..."
sudo apt install -y php7.4 php7.4-gd php7.4-json php7.4-mbstring php7.4-curl php7.4-xml php7.4-zip php7.4-mysql php7.4-intl php7.4-bz2 php7.4-imagick php7.4-fpm php7.4-cli libapache2-mod-php php7.4-sqlite3 php7.4-pgsql

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
instalar_servidor_samba() {
# Actualiza el sistema y las dependencias
echo "Actualizando el sistema..."
apt update && apt upgrade -y

# Instala Samba
echo "Instalando Samba..."
apt install samba -y

# Pide al usuario el nombre de la carpeta compartida
read -p "¿Cómo quieres llamar la carpeta compartida? " carpeta_compartida

# Pide al usuario si la carpeta debe ser escribible
read -p "¿Quieres que la carpeta sea escribible? (s/n): " escribible

# Crea la carpeta compartida en la ubicación predeterminada
ruta_carpeta="/srv/samba/$carpeta_compartida"
mkdir -p "$ruta_carpeta"

# Establece los permisos de la carpeta: leer y escribir para todos los usuarios
chmod 777 "$ruta_carpeta"  # Permiso de lectura/escritura para todos

# Asigna el propietario a 'nobody:nogroup' para Samba
chown nobody:nogroup "$ruta_carpeta"

# Configura la carpeta en Samba
SMB_CONF="/etc/samba/smb.conf"
echo "Configurando Samba..."

# Agrega la configuración al final del archivo smb.conf
{
    echo ""
    echo "[$carpeta_compartida]"
    echo "   path = $ruta_carpeta"
    echo "   available = yes"
    echo "   valid users = @sambashare"
    echo "   read only = no"
    echo "   browsable = yes"
    echo "   public = yes"
    if [[ "$escribible" == "s" || "$escribible" == "S" ]]; then
        echo "   writable = yes"
    else
        echo "   writable = no"
    fi
} >> "$SMB_CONF"

# Crear un grupo para los usuarios de Samba
groupadd sambashare

# Crear un usuario de Samba (si no existe)
read -p "Introduce el nombre de usuario de Samba para acceder a la carpeta: " usuario
useradd -m -G sambashare "$usuario"
echo "$usuario:1234" | chpasswd  # Establecer una contraseña por defecto (puede cambiarse)
smbpasswd -a "$usuario"  # Agregar el usuario a Samba
smbpasswd -e "$usuario"  # Habilitar el usuario en Samba

# Reiniciar el servicio de Samba
systemctl restart smbd
systemctl enable smbd

# Verificar el estado del servicio
if systemctl is-active --quiet smbd; then
    echo "El servicio Samba está corriendo correctamente."
else
    echo "Hubo un problema al iniciar el servicio Samba."
    exit 1
fi

# Mostrar la configuración y la carpeta compartida
echo "La carpeta compartida '$carpeta_compartida' ha sido configurada correctamente."
echo "Ruta compartida: //$HOSTNAME/$carpeta_compartida"
}

# Menú principal
while true; do
    echo "==================================================================="
    echo "=========================== ZenNet ================================"
    echo "==================================================================="
    echo "1) Configurar adaptadores de red"
    echo "2) Configurar gateway"
    echo "3) Configurar servidor DHCP"
    echo "4) Configurar servidor DNS local"
    echo "5) Configurar servidor SAMBA"
    echo "6) Configurar servidor SFTP"
    echo "7) Configurar Firewall"
    echo "8) Instalar Nextcloud 22.0.0"
    echo "9) Salir"
    read -p "Selecciona una opción: " opcion

    case $opcion in
        1) configurar_red ;;
        2) configurar_gateway ;;
        3) configurar_servidor_dhcp ;;
        4) configurar_servidor_dns ;;
        5) instalar_servidor_samba ;;
        6) instalar_servidor_sftp ;;
        7) configurar_firewall ;;
        8) nextcloud22.0.0_install ;;
        9) echo "Saliendo..."; break ;;
        *) echo "Opción no válida. Intenta de nuevo." ;;
    esac
done
