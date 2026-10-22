FROM ubuntu:24.04
LABEL maintainer="test@example.com"

RUN export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -qqy \
 && apt-get install -qqy --no-install-recommends \
apache2 \
libapache2-mod-php8.3 \
php8.3-curl \
php8.3-mysql \
php8.3-gd \
php8.3-xml \
php8.3-mbstring \
php8.3-zip \
php8.3-bcmath \
php8.3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN sed -i 's/variables_order = .*/variables_order = "EGPCS"/' /etc/php/8.3/apache2/php.ini

COPY docker/startup.sh /startup.sh
CMD ["/startup.sh"]
EXPOSE 80
