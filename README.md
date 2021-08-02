# Email Server Version 0.1.0
This is the repo for building Email Server on CentOS 7.6 for our Hepta Workshop.

## Permitted Server

| Owner                  | Hepta Workshop |
| ---------------------- | -------------- |
| Holder/Network Decider | Jiahe LI       |
| IP Public              | FORBIDDEN      |
| IP Private             | 10.0.4.17      |
| Password               | FORBIDDEN      |
| Version                | CentOS 7.6     |
| E-mail Monopolize      | YES            |

## Shell Script for Manipulation

```shell
# system update
yum -y update && \
yum -y install epel-release && \
yum -y update && \
yum -y install dovecot dovecot-mysql mariadb-server nginx opendkim php-fpm php-mbstring php-mysql php-xml postfix pypolicyd-spf tar wget # always enter 'y' to pass the queries

# configure MariaDB(MySQL-kind)
systemctl start mariadb
mysql_secure_installation # you can set passwd for root, and you can also ignore it.


```

