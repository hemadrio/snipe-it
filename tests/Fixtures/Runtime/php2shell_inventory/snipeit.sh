#!/bin/bash
# Fixture installer script for testing PHP version detection

install_packages () {
  apt-get install -y $PACKAGES
}

# Ubuntu 24.04
echo "* Installing Apache httpd, PHP, MariaDB and other requirements."
PACKAGES="mariadb-server mariadb-client apache2 libapache2-mod-php8.4 php8.4 php8.4-curl php8.4-mysql php8.4-gd"
install_packages

# Ubuntu 22.04
echo "* Installing Apache httpd, PHP, MariaDB and other requirements."
PACKAGES="mariadb-server mariadb-client apache2 libapache2-mod-php8.2 php8.2 php8.2-curl php8.2-mysql php8.2-gd"
install_packages

# Mint 22
echo "* Installing Apache httpd, PHP, MariaDB and other requirements."
PACKAGES="cron mariadb-server mariadb-client apache2 libapache2-mod-php8.3 php8.3 php8.3-curl php8.3-mysql"
install_packages

# Amazon Linux 2
amazon-linux-extras install -y php8.2
PACKAGES="httpd mariadb-server git unzip php php-mysqlnd"
install_packages
