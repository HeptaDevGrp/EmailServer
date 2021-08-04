# Email Server Version 0.8.4
This is the repo for building Email Server on CentOS 7.6 for our Hepta Workshop.

[TOC]

## Permitted Server

| Owner                           | Hepta Workshop     |
| ------------------------------- | ------------------ |
| Holder/Network Decider          | Jiahe LI           |
| IP Public                       | 81.68.236.207      |
| IP Private                      | 10.0.4.17          |
| Password                        | PRIVATE            |
| Version                         | CentOS 7.6         |
| E-mail Monopolize               | YES                |
| Domain Name                     | `hepta.asia`       |
| Second-level Domain Name        | `mail.hepta.asia`  |
| SSL Certification & Key Address | `/root/.cert_key/` |

## Overall Construction

The first-hand resource is [this website](https://zhuanlan.zhihu.com/p/28816035).

### Sending Process

![Architecture](http://jacklovespictures.oss-cn-beijing.aliyuncs.com/2021-08-03-071352.png)

### Encryption

![Encryption](http://jacklovespictures.oss-cn-beijing.aliyuncs.com/2021-08-03-072508.png)

## Shell Script for Manipulation

### 1. System Update & Download All Packages

```shell
# system update
yum -y update && \
yum -y install epel-release && \
yum -y update && \
yum -y install dovecot dovecot-mysql mariadb-server nginx opendkim php-fpm php-mbstring php-mysql php-xml postfix pypolicyd-spf tar wget # always enter 'y' to pass the queries
```

### 2. Back-end Database System Setup

```shell
# configure MariaDB(MySQL-kind). This database only verifies the domain, user, and alias
systemctl start mariadb
mysql_secure_installation # you can set passwd for root, and you can also ignore it. For later questions, use all 'y's to pass the queries.

# set-up MariaDB
mysql -u root -p # log in MariaDB using user root
CREATE USER 'mail_sys'@'localhost' IDENTIFIED BY 'mail_sys';
CREATE DATABASE mail_sys;
GRANT SELECT ON mail_sys.* TO 'mail_sys'@'localhost' IDENTIFIED BY 'mail_sys'; # grant arthority
FLUSH PRIVILEGES;
USE mail_sys;
CREATE TABLE `domains` ( `id` int(20) NOT NULL auto_increment, `name` varchar(100) NOT NULL, PRIMARY KEY (`id`) ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
REFERENCES domains(id) ON DELETE CASCADE ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
# REFERENCES domains(id) ON DELETE CASCADE ) ENGINE=InnoDB DEFAULT CHARSET=utf8; # for alias
INSERT INTO `mail_sys`.`domains` (`id` ,`name`) 
-> VALUES ('1', 'hepta.asia');
INSERT INTO `mail_sys`.`users`
-> (`id`, `domain_id`, `password` , `email`) VALUES
-> ('1', '1', ENCRYPT('12345678', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'ceo@example.com'),
-> ('2', '1', ENCRYPT('password', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'hr@example.com'),
-> ('3', '1', ENCRYPT('11111111', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'lyon@example.com');
SELECT * FROM mail_sys.domains;
SELECT * FROM mail_sys.users;
```

### 3. User Group Setup

```shell
# add user group
groupadd -g 2000 mail_sys
useradd -g mail_sys -u 2000 mail_sys -d /var/spool/mail -s /sbin/nologin
chown -R mail_sys:mail_sys /var/spool/mail
```

### 4. Postfix Setup

```shell
# postfix part
cp -r /etc/postfix /etc/postfix.bak # back-up

cat > /etc/postfix/main.cf << EOF
{
mydomain = hepta.asia
myhostname = mail.hepta.asia
mydestination = localhost
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mynetworks = 127.0.0.0/8
mailbox_size_limit = 0
recipient_delimiter = +
inet_protocols = all
inet_interfaces = all
smtp_address_preference = ipv4
smtpd_banner = ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
virtual_transport = lmtp:unix:private/dovecot-lmtp
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
virtual_mailbox_domains = mysql:/etc/postfix/mysql_mailbox_domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql_mailbox_maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql_alias_maps.cf
smtpd_sender_login_maps = mysql:/etc/postfix/mysql_mailbox_maps.cf, mysql:/etc/postfix/mysql_alias_maps.cf
disable_vrfy_command = yes
strict_rfc821_envelopes = yes
smtpd_sender_restrictions = reject_non_fqdn_sender, reject_unknown_sender_domain, reject_sender_login_mismatch
smtpd_recipient_restrictions = reject_non_fqdn_recipient, reject_unknown_recipient_domain, permit_sasl_authenticated, reject_unauth_destination, check_policy_service unix:private/policyd-spf
virtual_uid_maps = static:2000
virtual_gid_maps = static:2000
message_size_limit = 102400000
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_cert_file=/root/.cert_key/cert.pem
smtpd_tls_key_file=/root/.cert_key/key.pem
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_tls_protocols = TLSv1.2, TLSv1.1, !TLSv1, !SSLv2, !SSLv3
smtp_tls_protocols = TLSv1.2, TLSv1.1, !TLSv1, !SSLv2, !SSLv3
smtp_tls_ciphers = high
smtpd_tls_ciphers = high
smtpd_tls_mandatory_protocols = TLSv1.2, TLSv1.1, !TLSv1, !SSLv2, !SSLv3
smtp_tls_mandatory_protocols = TLSv1.2, TLSv1.1, !TLSv1, !SSLv2, !SSLv3
smtp_tls_mandatory_ciphers = high
smtpd_tls_mandatory_ciphers = high
smtpd_tls_mandatory_exclude_ciphers = MD5, DES, ADH, RC4, PSD, SRP, 3DES, eNULL, aNULL
smtpd_tls_exclude_ciphers = MD5, DES, ADH, RC4, PSD, SRP, 3DES, eNULL, aNULL
smtp_tls_mandatory_exclude_ciphers = MD5, DES, ADH, RC4, PSD, SRP, 3DES, eNULL, aNULL
smtp_tls_exclude_ciphers = MD5, DES, ADH, RC4, PSD, SRP, 3DES, eNULL, aNULL
tls_preempt_cipherlist = yes
smtpd_tls_received_header = yes
policyd-spf_time_limit = 3600
EOF
}

cat > /etc/postfix/master.cf << EOF
{
smtp      inet  n       -       n       -       -       smtpd
submission inet n       -       n       -       -       smtpd
       -o smtpd_tls_security_level=encrypt
smtps     inet  n       -       n       -       -       smtpd
       -o smtpd_tls_wrappermode=yes
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
       -o smtp_helo_timeout=120 -o smtp_connect_timeout=120
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
policyd-spf    unix  -       n       n       -       0       spawn
       user=mail_sys argv=/usr/libexec/postfix/policyd-spf
EOF
}

cat > /etc/postfix/mysql_mailbox_domains.cf << EOF
{
user = mail_sys
password = mail_sys
hosts = localhost
dbname = mail_sys
query = SELECT 1 FROM domains WHERE name='%s'
EOF
}

cat > /etc/postfix/mysql_mailbox_maps.cf << EOF
{
user = mail_sys
password = mail_sys
hosts = localhost
dbname = mail_sys
query = SELECT email FROM users WHERE email='%s'
EOF
}
```

```shell
# postfix setup
systemctl start postfix
postmap -q hepta.asia mysql:/etc/postfix/mysql_mailbox_domains.cf # should return 1
postmap -q ceo@hepta.asia mysql:/etc/postfix/mysql_alias_maps.cf # should return ceo@hepta.asia
systemctl stop postfix # temporarily shut down
```

### 5. Devocot Setup

```shell
# dovecot setup
cp -r /etc/dovecot /etc/dovecot.bak

cat > /etc/dovecot/dovecot.conf << EOF
{
protocols = imap lmtp
dict {
}
!include conf.d/*.conf
!include_try local.conf
EOF
}

cat > /etc/dovecot/conf.d/10-mail.conf << EOF
namespace inbox {
  inbox = yes
}
first_valid_uid = 1000
mbox_write_locks = fcntl
mail_location = maildir:/var/spool/mail/%d/%n
mail_privileged_group = mail
EOF

cat > /etc/dovecot/conf.d/15-mailboxes.conf << EOF
{
namespace inbox {
  mailbox Drafts {
    auto = create
    special_use = \Drafts
  }
  mailbox Trash {
    auto = create
    special_use = \Trash
  }
  mailbox Sent {
    auto = create
    special_use = \Sent
  }
}
EOF
}

cat > /etc/dovecot/conf.d/10-auth.conf << EOF
{
auth_mechanisms = plain login
!include auth-sql.conf.ext
EOF
}

cat > /etc/dovecot/conf.d/auth-sql.conf.ext << EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=mail_sys gid=mail_sys home=/var/spool/mail/%d/%n
}
EOF

cat > /etc/dovecot/dovecot-sql.conf.ext << EOF
{
driver = mysql
connect = host=localhost dbname=mail_sys user=mail_sys password=mail_sys
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';
EOF
}

cat > /etc/dovecot/conf.d/10-ssl.conf << EOF
{
ssl = required
ssl_cert = </root/.cert_key/cert.pem
ssl_key = </root/.cert_key/key.pem
ssl_protocols = TLSv1.2 TLSv1.1 !TLSv1 !SSLv2 !SSLv3
ssl_cipher_list = ALL:!MD5:!DES:!ADH:!RC4:!PSD:!SRP:!3DES:!eNULL:!aNULL
EOF
}

cat > /etc/dovecot/conf.d/10-master.conf << EOF
{
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service lmtp {
    unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service imap {

}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }

  unix_listener auth-userdb {
    mode = 0600
    user = mail_sys
  }
  user = dovecot
}

service auth-worker {
  user = mail_sys
}
EOF
}

cat > /etc/dovecot/conf.d/15-lda.conf << EOF
{
postmaster_address = postmaster@%d

protocol lda {
}
EOF
}
```

### 6. OpenDKIM Setup

```shell
cat > /etc/opendkim.conf << EOF
{
Syslog yes
UMask 002
OversignHeaders From
Socket inet:8891@127.0.0.1
Domain hepta.asia
KeyFile /etc/opendkim/keys/mail.private
Selector mail
RequireSafeKeys no
EOF
}

opendkim-genkey -D /etc/opendkim/keys/ -d hepta.asia -s mail && \
chown -R opendkim:opendkim /etc/opendkim/keys/

cat >> /etc/postfix/main.cf << EOF
{
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891
EOF
}
```

### 7. Services Start (postfix, dovecot, opendkim)

```shell
systemctl start postfix dovecot opendkim
systemctl enable postfix dovecot opendkim mariadb # start when booting
```

### 8. Records Setup

| Record Type | Record HostName | Record Value                                                 |
| ----------- | --------------- | ------------------------------------------------------------ |
| A           | @               | 1.1.1.1                                                      |
| MX          | @               | mail.hepta.asia                                              |
| A           | mail            | 1.1.1.1                                                      |
| TXT         | @               | v=spf1 mx -all                                               |
| TXT         | _dmarc          | v=DMARC1; p=reject                                           |
| TXT         | mail._domainkey | v=DKIM1; k=rsa; <br/>p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBG8b8e8+K5VPYDMbMiwXjZTFWIUWn1/pUD09Qc3FxtmCqBXqCD9833cWz1yeI1IHX9zvAIIE38o9TjvUn2kk/GMypn4NKo/EiF5hsLYPpj24OvR1u87ILgSco0WKe43UNWeoKlW9kmSQBFE49nFsJlZ3Kw0PFkBRSvQzc5HKwDQIDAQAB |
|             |                 |                                                              |

![image-20210803123133095](http://jacklovespictures.oss-cn-beijing.aliyuncs.com/2021-08-03-043133.png)

### 9. RoundCubeMail Setup

```shell
wget https://github.com/roundcube/roundcubemail/releases/download/1.3.0/roundcubemail-1.3.0-complete.tar.gz
tar -xf roundcubemail-1.3.0-complete.tar.gz && \
mv roundcubemail-1.3.0 /usr/share/roundcube && \
chown -R apache:apache /usr/share/roundcube
```

### 10. NGINX Setup

```shell
vi /etc/nginx/conf.d/mail.conf

server {
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
}
# :x
```

### 11. PHP & Apache Setup

```shell
echo "date.timezone = Asia/Shanghai" >> /etc/php.ini 
mkdir /var/lib/php/session && \
chown apache:apache /var/lib/php/session
```

### 12. Grant RoundCubeMail Through MariaDB

```shell
# database operations
mysql -u root -p
CREATE USER 'roundcube'@'localhost' IDENTIFIED BY 'roundcube';
CREATE DATABASE roundcube;
GRANT ALL ON roundcube.* TO 'roundcube'@'localhost' IDENTIFIED BY 'roundcube';
FLUSH PRIVILEGES;
# ctrl + D
```

### 13. Services Start (NGINX, PHP)

```shell
# start the services (except MariaDB)
systemctl enable nginx php-fpm
systemctl start nginx php-fpm
```

### 14. Restart All Services

```shell
nginx -s reload
systemctl restart postfix dovecot opendkim nginx php-fpm
```

