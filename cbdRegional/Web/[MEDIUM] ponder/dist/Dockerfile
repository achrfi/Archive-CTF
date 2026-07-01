FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    APP_URL=http://localhost:5000/ \
    BOT_URL=http://localhost:3001 \
    FLAG=CBC{redacted} \
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=redacted \
    ADMIN_UPLOAD_FILENAME=admin-private.gif

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        fonts-liberation \
        nodejs \
        npm \
        curl \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/webapp

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /tmp/requirements.txt

COPY webapp/ /opt/webapp/
COPY bot/package*.json /opt/bot/
WORKDIR /opt/bot
RUN npm install --omit=dev
COPY bot/ /opt/bot/

COPY conf/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY reset-state-loop.sh /usr/local/bin/reset-state-loop.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/reset-state-loop.sh \
    && mkdir -p /opt/webapp/instance/uploads \
    && adduser --disabled-password --gecos "" appuser \
    && chown -R appuser:appuser /opt/webapp /opt/bot

EXPOSE 5000

ENTRYPOINT ["docker-entrypoint.sh"]
