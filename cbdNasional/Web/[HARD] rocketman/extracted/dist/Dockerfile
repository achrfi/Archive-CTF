FROM wordpress

RUN a2enmod proxy proxy_http
RUN sed -ri 's/^Listen 80$/Listen 9100/' /etc/apache2/ports.conf \
    && sed -ri 's/:80>/:9100>/' /etc/apache2/sites-available/000-default.conf

COPY docker/apache/report-bot.conf /etc/apache2/conf-enabled/report-bot.conf
COPY --chown=www-data:www-data challenge-custom/plugin-custom/ /usr/src/wordpress/wp-content/plugins/plugin-custom/

COPY --chown=www-data:www-data challenge-custom/flag.txt /flag.txt
RUN chmod 400 /flag.txt
