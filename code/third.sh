wget https://github.com/roundcube/roundcubemail/releases/download/1.3.0/roundcubemail-1.3.0-complete.tar.gz
tar -xf roundcubemail-1.3.0-complete.tar.gz && \
mv roundcubemail-1.3.0 /usr/share/roundcube && \
chown -R apache:apache /usr/share/roundcube

echo 'server {
    listen       80;
    server_name  mail.hepta.asia;
    return 301 https://$server_name$request_uri;
}

server {
    listen       443 ssl http2;
    server_name  mail.hepta.asia;
    ssl_certificate "/root/.cert_key/cert.pem";
    ssl_certificate_key "/root/.cert_key/key.pem";
    add_header Strict-Transport-Security "max-age=15552000; includeSubDomains";
    location / {
     root         /usr/share/roundcube;
     index        index.php;
    }
    location ~ .php$ {
        root         /usr/share/roundcube;
        fastcgi_pass   127.0.0.1:9000;
        fastcgi_index  index.php;
        fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
        include        fastcgi_params;
    }
}' > /etc/nginx/conf.d/mail.conf

echo "date.timezone = Asia/Shanghai" >> /etc/php.ini
mkdir /var/lib/php/session && \
chown apache:apache /var/lib/php/session

# database operations
mysql -u root -p

CREATE USER 'roundcube'@'localhost' IDENTIFIED BY 'roundcube';
CREATE DATABASE roundcube;
GRANT ALL ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY 'roundcube';
FLUSH PRIVILEGES;
# ctrl + D

# start the services (except MariaDB)
systemctl enable nginx php-fpm
systemctl start nginx php-fpm

nginx -s reload
systemctl restart postfix dovecot opendkim nginx php-fpm
