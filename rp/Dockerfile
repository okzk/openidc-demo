FROM debian

RUN apt-get update \
  && apt-get install apache2 libapache2-mod-auth-openidc libapache2-mod-php -y

COPY apache2.conf /etc/apache2/apache2.conf
COPY index.php /var/www/html/protected/

ENV ACCESS_LOG=/dev/stdout \
  ERROR_LOG=/dev/stderr \
  LOG_LEVEL=warn \
  FQDN=localhost

EXPOSE 80
CMD ["/usr/sbin/apache2", "-D", "FOREGROUND"]

