
sudo su

DEBIAN_FRONTEND=noninteractive
sudo apt-get update && sudo apt-get -y upgrade

#Allow root login!
sed -i 's/.*ssh-rsa/ssh-rsa/' /root/.ssh/authorized_keys

#Add LAMP
apt-get install tasksel -y
tasksel

#For landing page
apt-get install php-intl -y

#For reporting page
apt-get install php-mbstring -y

service apache2 restart

#Security.txt
echo 'This system is in use for the purpose of security awareness training (which may include authorised phishing campaigns) at your organisation. Please contact your security department to discuss these activites.' > /var/www/html/security.txt

#For TLS Cert
apt-get install software-properties-common -y
add-apt-repository universe
add-apt-repository ppa:certbot/certbot -y
apt-get update
apt-get install certbot python-certbot-apache -y

certbot --apache






