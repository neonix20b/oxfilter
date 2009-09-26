set follow-fork-mode child
run -D DEFAULT_VHOST -D INFO -D LANGUAGE -D SSL -D SSL_DEFAULT_VHOST -D PHP5 -d /usr/lib/apache2 -f /etc/apache2/httpd.conf -k start

