# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# 1) Системні інструменти, які майже завжди стають у пригоді:
#    - openssh-client  — ssh/scp для підключень до Proxmox
#    - wget, curl      — завантаження скриптів/артефактів
#    - ca-certificates — https сертифікати
#    - jq              — зручно парсити JSON у дебазі
#    - unzip, tar, xz-utils — розпаковка архівів (zip/tar.xz)
#    - procps, iputils-ping, dnsutils, net-tools — діагностика мережі/процесів
#    - git             — інколи стане у пригоді і всередині контролера
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    wget \
    curl \
    ca-certificates \
    jq \
    unzip \
    tar \
    xz-utils \
    procps \
    iputils-ping \
    dnsutils \
    net-tools \
    git \
 && rm -rf /var/lib/apt/lists/*

# 2) Python-залежності
COPY controller/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3) Код
COPY controller/ .
COPY openapi.json /app/openapi.json

# 4) Сервіс
ENV PORT=8000
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
