# Proxmox LLM Controller

Цей репозиторій містить повноцінний приклад інтеграції локальної LLM‑системи з Proxmox VE. Він складається з:

* **docker‑compose.yml** – піднімає Ollama, OpenWebUI та Python‑сервіс для керування Proxmox. Ці контейнери взаємодіють між собою через внутрішню мережу.
* **controller/** – вихідний код Python‑сервісу. Це FastAPI застосунок, що підключається до API Proxmox за допомогою бібліотеки `proxmoxer` та надає прості REST‑ендпоінти для списку вузлів, списку LXC‑контейнерів, створення нових LXC і запуску/зупинки контейнерів.

## Використання

1. Скопіюйте репозиторій на свій хост Proxmox або будь‑який інший сервер із доступом до Proxmox API.
2. Створіть файл `.env` у корені каталогу та заповніть такі змінні:

   ```env
   PROXMOX_HOST=your-proxmox-host:8006
   PROXMOX_USER=root@pam
   PROXMOX_TOKEN_NAME=exampleToken
   PROXMOX_TOKEN_VALUE=superSecret
   PROXMOX_VERIFY_SSL=False
   ```

   > Щоб згенерувати API‑токен у Proxmox, відкрийте *Datacenter* → *Permissions* → *API Tokens*.

3. Запустіть стек командою:

   ```sh
   docker-compose up -d
   ```

   Після запуску:
   * Ollama API доступний на порті `11434`.
   * OpenWebUI доступна на порті `3000`.
   * Контролер Proxmox доступний на порті `8000` (використовується FastAPI).

## Виклик API

Використовуйте будь‑який HTTP‑клієнт (curl, Postman, Python `requests`) для взаємодії з контролером:

* **Список вузлів**

  ```sh
  curl http://localhost:8000/nodes
  ```

* **Список LXC на вузлі**

  ```sh
  curl http://localhost:8000/lxc/pve
  ```

* **Створення LXC**

  ```sh
  curl -X POST http://localhost:8000/lxc \
    -H "Content-Type: application/json" \
    -d '{
          "node": "pve",          
          "vmid": 105,
          "ostemplate": "local:vztmpl/debian-12-standard.tar.zst",
          "cores": 2,
          "memory": 2048,
          "hostname": "test-lxc",
          "net0": "name=eth0,bridge=vmbr0,ip=192.168.1.105/24,gw=192.168.1.1",
          "password": "password",
          "features": {"nesting": 1, "keyctl": 1}
      }'
  ```

## Архітектура

Локальна LLM, розгорнута через Ollama, може спілкуватися з FastAPI‑контролером і віддавати завдання (наприклад, створити контейнер) у вигляді JSON. Контролер виконує виклики до Proxmox API з допомогою `proxmoxer` й повертає результат у зручному форматі. Такий підхід дозволяє відокремити LLM від прямого root‑доступу на хості, реалізувати фільтрацію та логування, і легко розширювати функціональність.