FROM php:8.3-cli-alpine

ENV DOCKERIZE_VERSION=v0.6.1

RUN apk add --no-cache \
      curl \
      make \
      mysql-client \
      openssl \
      wget \
    && apk add --no-cache --virtual .build-deps $PHPIZE_DEPS \
    && docker-php-ext-install mysqli \
    && apk del .build-deps \
    && curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp-cli \
    && chmod +x /usr/local/bin/wp-cli \
    && wget -q https://github.com/jwilder/dockerize/releases/download/${DOCKERIZE_VERSION}/dockerize-alpine-linux-amd64-${DOCKERIZE_VERSION}.tar.gz \
    && tar -C /usr/local/bin -xzf dockerize-alpine-linux-amd64-${DOCKERIZE_VERSION}.tar.gz \
    && rm dockerize-alpine-linux-amd64-${DOCKERIZE_VERSION}.tar.gz

COPY docker/wordpress/toolbox/Makefile /scripts/Makefile
COPY challenge-custom/plugin-custom/ /plugins/plugin-custom/

ENTRYPOINT ["make", "-f", "/scripts/Makefile"]
