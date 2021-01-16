FROM php:7.3-apache

RUN apt-get update && \
    apt-get install -y zlib1g-dev libzip-dev

COPY trackr-virtualhost.conf /etc/apache2/sites-available/000-default.conf
COPY php.ini /usr/local/etc/php/php.ini
COPY apache2.conf /etc/apache2/apache2.conf

RUN docker-php-ext-install pdo pdo_mysql zip

WORKDIR /var/www/html

RUN a2enmod rewrite
RUN service apache2 restart