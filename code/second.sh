# system update & download all packages
yum -y update
yum -y install epel-release
yum -y update
yum -y install dovecot dovecot-mysql mariadb-server nginx opendkim php-fpm php-mbstring php-mysql php-xml postfix pypolicyd-spf tar wget # always enter 'y' to pass the queries

# configure MariaDB(MySQL-kind). This database only verifies the domain, user, and alias
systemctl start mariadb
mysql_secure_installation # Do not set passwd for MySQL here.

# set-up MariaDB
mysql -u root # log in MariaDB using user root

CREATE USER 'mail_sys'@'localhost' IDENTIFIED BY 'mail_sys';
CREATE DATABASE mail_sys;
GRANT SELECT ON mail_sys.* TO 'mail_sys'@'localhost' IDENTIFIED BY 'mail_sys'; # grant arthority
FLUSH PRIVILEGES;
USE mail_sys;
CREATE TABLE `domains` ( `id` int(20) NOT NULL auto_increment, `name` varchar(100) NOT NULL, PRIMARY KEY (`id`) ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE `users` ( `id` int(20) NOT NULL auto_increment, `domain_id` int(20) NOT NULL, `password` varchar(200) NOT NULL, `email` varchar(200) NOT NULL, PRIMARY KEY (`id`), UNIQUE KEY `email` (`email`), FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
INSERT INTO `mail_sys`.`domains` (`id` ,`name`) VALUES ('1', 'hepta.asia');
INSERT INTO `mail_sys`.`users` (`id`, `domain_id`, `password` , `email`) VALUES ('1', '1', ENCRYPT('12345678', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'ceo@hepta.asia'),('2', '1', ENCRYPT('password', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'hr@hepta.asia'), ('3', '1', ENCRYPT('11111111', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))), 'lyon@hepta.asia');
SELECT * FROM mail_sys.domains;
SELECT * FROM mail_sys.users;
exit

# add user group
groupadd -g 2000 mail_sys
useradd -g mail_sys -u 2000 mail_sys -d /var/spool/mail -s /sbin/nologin
chown -R mail_sys:mail_sys /var/spool/mail

# postfix part
cp -r /etc/postfix /etc/postfix.bak # back-up

echo 'mydomain = hepta.asia
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
policyd-spf_time_limit = 3600' > /etc/postfix/main.cf

echo 'smtp      inet  n       -       n       -       -       smtpd
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
       user=mail_sys argv=/usr/libexec/postfix/policyd-spf' > /etc/postfix/master.cf

echo 'user = mail_sys
password = mail_sys
hosts = localhost
dbname = mail_sys
query = SELECT 1 FROM domains WHERE name='%s'' > /etc/postfix/mysql_mailbox_domains.cf

echo 'user = mail_sys
password = mail_sys
hosts = localhost
dbname = mail_sys
query = SELECT email FROM users WHERE email='%s'' > /etc/postfix/mysql_mailbox_maps.cf

# postfix setup
systemctl start postfix
postmap -q hepta.asia mysql:/etc/postfix/mysql_mailbox_domains.cf # should return 1
postmap -q ceo@hepta.asia mysql:/etc/postfix/mysql_mailbox_maps.cf # should return ceo@hepta.asia
systemctl stop postfix # temporarily shut down

# dovecot setup
cp -r /etc/dovecot /etc/dovecot.bak

echo 'protocols = imap lmtp
dict {
}
!include conf.d/*.conf
!include_try local.conf' > /etc/dovecot/dovecot.conf

echo 'namespace inbox {
  inbox = yes
}
first_valid_uid = 1000
mbox_write_locks = fcntl
mail_location = maildir:/var/spool/mail/%d/%n
mail_privileged_group = mail' > /etc/dovecot/conf.d/10-mail.conf

echo 'namespace inbox {
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
}' > /etc/dovecot/conf.d/15-mailboxes.conf

echo 'auth_mechanisms = plain login
!include auth-sql.conf.ext' > /etc/dovecot/conf.d/10-auth.conf

echo 'passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
userdb {
  driver = static
  args = uid=mail_sys gid=mail_sys home=/var/spool/mail/%d/%n
}' > /etc/dovecot/conf.d/auth-sql.conf.ext

echo 'driver = mysql
connect = host=localhost dbname=mail_sys user=mail_sys password=mail_sys
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM users WHERE email='%u';' > /etc/dovecot/dovecot-sql.conf.ext

echo 'ssl = required
ssl_cert = </root/.cert_key/cert.pem
ssl_key = </root/.cert_key/key.pem
ssl_protocols = TLSv1.2 TLSv1.1 !TLSv1 !SSLv2 !SSLv3
ssl_cipher_list = ALL:!MD5:!DES:!ADH:!RC4:!PSD:!SRP:!3DES:!eNULL:!aNULL' > /etc/dovecot/conf.d/10-ssl.conf

echo 'service imap-login {
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
}' > /etc/dovecot/conf.d/10-master.conf

echo 'postmaster_address = postmaster@%d

protocol lda {
}' > /etc/dovecot/conf.d/15-lda.conf

echo 'Syslog yes
UMask 002
OversignHeaders From
Socket inet:8891@127.0.0.1
Domain hepta.asia
KeyFile /etc/opendkim/keys/mail.private
Selector mail
RequireSafeKeys no' > /etc/opendkim.conf

opendkim-genkey -D /etc/opendkim/keys/ -d hepta.asia -s mail && \
chown -R opendkim:opendkim /etc/opendkim/keys/

echo 'milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:127.0.0.1:8891
non_smtpd_milters = inet:127.0.0.1:8891' >> /etc/postfix/main.cf

systemctl start postfix dovecot opendkim
systemctl enable postfix dovecot opendkim mariadb # start when booting

# now turn to Tencent Cloud to configure the domain-name records
