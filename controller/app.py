import os
import logging
from functools import lru_cache
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from proxmoxer import ProxmoxAPI

# ─────────────────────────────────────────────
# Логування
# ─────────────────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("proxmox-controller")

# ─────────────────────────────────────────────
# FastAPI
# ─────────────────────────────────────────────
app = FastAPI(title="Proxmox LLM Controller", version="1.1.0")

# За потреби дозволь CORS (наприклад, якщо викликаєш з OpenWebUI у іншому походженні)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Схеми запитів
# ─────────────────────────────────────────────
class StartStopReq(BaseModel):
    node: str
    vmid: int


class CreateLXCReq(BaseModel):
    node: str
    vmid: int
    hostname: str

    # Ресурси
    cores: int = 2
    memory: int = 2048  # MB

    # Диск/сховище
    storage: str
    rootfs_gb: int = 16

    # Мережа
    bridge: str = "vmbr0"
    ip_cidr: Optional[str] = None  # напр. "192.168.1.150/24"
    gateway: Optional[str] = None

    # Аутентифікація/доступ всередині LXC
    ssh_public_key: Optional[str] = None
    password: Optional[str] = None  # тимчасовий пароль root у контейнері

    # Особливості LXC
    unprivileged: bool = True
    features: Optional[Dict[str, int]] = None  # напр. {"nesting":1,"keyctl":1,"fuse":1}

    # Шаблон ОС (обов’язково для створення LXC у Proxmox)
    # приклад: "local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst"
    ostemplate: str

    # Стартувати після створення
    start: bool = True

    @field_validator("cores")
    @classmethod
    def _min_cores(cls, v: int) -> int:
        if v < 1:
            raise ValueError("cores must be >= 1")
        return v

    @field_validator("memory")
    @classmethod
    def _min_memory(cls, v: int) -> int:
        if v < 128:
            raise ValueError("memory must be >= 128 MB")
        return v

    @field_validator("rootfs_gb")
    @classmethod
    def _min_rootfs(cls, v: int) -> int:
        if v < 4:
            raise ValueError("rootfs_gb must be >= 4 GB")
        return v


# ─────────────────────────────────────────────
# Допоміжні функції
# ─────────────────────────────────────────────
def _features_dict_to_str(features: Dict[str, int]) -> str:
    """
    Перетворює {"nesting":1, "keyctl":1} -> "nesting=1;keyctl=1"
    """
    return ";".join(f"{k}={v}" for k, v in features.items())


@lru_cache(maxsize=1)
def get_proxmox() -> ProxmoxAPI:
    """
    Створює та кешує клієнт ProxmoxAPI.
    Підтримує як токен (рекомендовано), так і пароль.
    """
    host = os.getenv("PROXMOX_HOST")
    user = os.getenv("PROXMOX_USER")  # формат типово: "root@pam"
    realm = os.getenv("PROXMOX_REALM", "pam")
    token_name = os.getenv("PROXMOX_TOKEN_NAME")
    token_value = os.getenv("PROXMOX_TOKEN_VALUE")
    password = os.getenv("PROXMOX_PASSWORD")
    verify_ssl_env = os.getenv("VERIFY_SSL", "False").strip().lower()
    verify_ssl = verify_ssl_env in ("1", "true", "yes")
    port = int(os.getenv("PROXMOX_PORT", "8006"))

    if not host:
        raise RuntimeError("Missing PROXMOX_HOST")
    if not user:
        # Якщо у .env задали окремо USER без realm – підставимо
        user = f"root@{realm}"

    kwargs: Dict[str, Any] = {
        "user": user,
        "verify_ssl": verify_ssl,
        "port": port,
        "backend": "https",
    }

    if token_name and token_value:
        kwargs["token_name"] = token_name
        kwargs["token_value"] = token_value
        log.info("Using Proxmox API token authentication.")
    elif password:
        kwargs["password"] = password
        log.warning("Using password auth (consider API token instead).")
    else:
        raise RuntimeError(
            "Provide either PROXMOX_TOKEN_NAME + PROXMOX_TOKEN_VALUE or PROXMOX_PASSWORD."
        )

    log.info("Connecting to Proxmox at https://%s:%s (verify_ssl=%s)", host, port, verify_ssl)
    return ProxmoxAPI(host, **kwargs)


def _http_500(detail: str) -> HTTPException:
    log.exception(detail)
    return HTTPException(status_code=500, detail=detail)


# ─────────────────────────────────────────────
# Ендпойнти
# ─────────────────────────────────────────────
@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/version")
def pve_version() -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        return prox.version.get()
    except Exception as e:
        raise _http_500(f"/version failed: {e}")


@app.get("/nodes")
def list_nodes() -> List[Dict[str, Any]]:
    try:
        prox = get_proxmox()
        return prox.nodes.get()
    except Exception as e:
        raise _http_500(f"/nodes failed: {e}")


@app.get("/lxc")
def list_lxc(node: str = Query(..., description="Назва вузла Proxmox (наприклад, 'pve')")) -> List[Dict[str, Any]]:
    try:
        prox = get_proxmox()
        return prox.nodes(node).lxc.get()
    except Exception as e:
        raise _http_500(f"/lxc failed: {e}")


@app.post("/lxc/start")
def start_lxc(req: StartStopReq) -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        res = prox.nodes(req.node).lxc(req.vmid).status.start.post()
        return {"ok": True, "task": res}
    except Exception as e:
        raise _http_500(f"/lxc/start failed: {e}")


@app.post("/lxc/stop")
def stop_lxc(req: StartStopReq) -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        res = prox.nodes(req.node).lxc(req.vmid).status.stop.post()
        return {"ok": True, "task": res}
    except Exception as e:
        raise _http_500(f"/lxc/stop failed: {e}")


@app.post("/lxc/create")
def create_lxc(req: CreateLXCReq) -> Dict[str, Any]:
    """
    Створює LXC з вказаного vz-шаблону (ostemplate) та базовою конфігурацією.
    Вимоги:
      - ostemplate: наприклад "local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst"
      - storage: назва storage (де створити rootfs)
    """
    try:
        prox = get_proxmox()

        payload: Dict[str, Any] = {
            "vmid": req.vmid,
            "hostname": req.hostname,
            "cores": req.cores,
            "memory": req.memory,
            "ostemplate": req.ostemplate,                    # обов'язково
            "storage": req.storage,
            "rootfs": f"{req.storage}:{req.rootfs_gb}",      # прикріплення диска
            "unprivileged": int(req.unprivileged),
        }

        # Мережа
        if req.bridge:
            payload["net0"] = f"name=eth0,bridge={req.bridge}"
        if req.ip_cidr:
            payload["ip"] = req.ip_cidr
        if req.gateway:
            payload["gw"] = req.gateway

        # Доступ усередині контейнера
        if req.ssh_public_key:
            payload["ssh-public-keys"] = req.ssh_public_key
        if req.password:
            payload["password"] = req.password

        # Особливості LXC
        if req.features:
            payload["features"] = {k: bool(v) for k, v in req.features.items()}

        # Створення
        task = prox.nodes(req.node).lxc.post(**payload)

        # За потреби – автозапуск після створення
        if req.start:
            prox.nodes(req.node).lxc(req.vmid).status.start.post()

        return {"created": True, "task": task, "vmid": req.vmid}
    except Exception as e:
        raise _http_500(f"/lxc/create failed: {e}")


# ─────────────────────────────────────────────
# Uvicorn launcher (корисно для локального запуску/дебагу)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
