import os
import json
import shlex
import logging
import subprocess
from io import StringIO
from functools import lru_cache
from typing import Optional, Dict, Any, List, Tuple, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from proxmoxer import ProxmoxAPI
import paramiko

# ─────────────────────────────────────────────
# Логування
# ─────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("universal-controller")

# ─────────────────────────────────────────────
# FastAPI
# ─────────────────────────────────────────────
app = FastAPI(title="Universal LLM Controller", version="2.0.0")

# CORS (наприклад, якщо викликаєш з OpenWebUI з іншого походження)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.getenv("CORS_ALLOW_ORIGINS", "*").split(",")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Моделі запитів
# ─────────────────────────────────────────────
class StartStopReq(BaseModel):
    node: Optional[str] = None  # може бути не заданий
    vmid: int


class CreateLXCReq(BaseModel):
    node: Optional[str] = None
    vmid: int
    hostname: str
    cores: int = 2
    memory: int = 2048  # MB
    storage: str
    rootfs_gb: int = 16
    bridge: str = "vmbr0"
    ip_cidr: Optional[str] = None  # напр. "192.168.1.150/24"
    gateway: Optional[str] = None
    ssh_public_key: Optional[str] = None
    password: Optional[str] = None      # тимчасовий пароль root у контейнері
    unprivileged: bool = True
    features: Optional[Dict[str, int]] = None  # напр. {"nesting":1,"keyctl":1}
    ostemplate: str                        # "local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst"
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


class LXCExecSpec(BaseModel):
    vmid: int
    cmd: str

    @field_validator("cmd")
    @classmethod
    def allowlist(cls, v: str):
        allowed = [
            "systemctl ", "service ", "journalctl ", "ls ", "cat ", "tail ",
            "head ", "df ", "du ", "ps ", "kill ", "docker ", "git ",
            "curl ", "wget ", "python3 ", "pip ", "bash ", "sh ",
            "apt ", "apt-get "
        ]
        if not any(v.startswith(p) for p in allowed):
            raise ValueError(f"Command not allowed. Allowed prefixes: {allowed}")
        return v


class DeploySpec(BaseModel):
    target_vmid: int
    repo_url: str
    workdir: str = "/opt/app"
    setup: List[str] = Field(default_factory=lambda: [
        "apt-get update",
        "apt-get install -y git curl python3 python3-venv"
    ])
    commands: List[str] = Field(default_factory=lambda: [
        "git clone {{repo_url}} {{workdir}} || (rm -rf {{workdir}} && git clone {{repo_url}} {{workdir}})",
        "cd {{workdir}} && if [ -f requirements.txt ]; then python3 -m venv .venv && . .venv/bin/activate && pip install -U pip -r requirements.txt; fi",
        "cd {{workdir}} && if [ -f docker-compose.yml ]; then curl -fsSL https://get.docker.com | sh && systemctl start docker && docker compose up -d; fi",
        "cd {{workdir}} && if [ -f Makefile ]; then make run || true; fi"
    ])


class SSHSpec(BaseModel):
    host: str
    user: str = "root"
    port: int = 22
    cmd: str
    key_path: Optional[str] = None
    key_data_b64: Optional[str] = None  # base64(OpenSSH private key)
    password: Optional[str] = None
    strict_host_key: bool = False
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None


class AppLaunchSpec(BaseModel):
    host: str
    user: str = "root"
    port: int = 22
    key_path: Optional[str] = None
    key_data_b64: Optional[str] = None
    password: Optional[str] = None
    strict_host_key: bool = False
    program: str = Field(..., description="firefox | google-chrome | chromium | code | xterm | tmux | bash ...")
    args: List[str] = Field(default_factory=list)
    env: Optional[Dict[str, str]] = None
    cwd: Optional[str] = None
    background: bool = True
    display: Optional[str] = Field(default=None, description="Напр., ':0' для GUI X11 хоста")


class BrowserSpec(BaseModel):
    host: str
    user: str = "root"
    port: int = 22
    key_path: Optional[str] = None
    key_data_b64: Optional[str] = None
    password: Optional[str] = None
    strict_host_key: bool = False

    action: Literal["open", "screenshot", "pdf"] = "open"
    url: str
    headless: bool = True
    browser_cmds: List[str] = Field(default_factory=lambda: ["google-chrome", "chromium-browser", "chromium"])
    window_size: str = "1280,800"
    user_data_dir: Optional[str] = None
    output_path: Optional[str] = Field(default=None, description="для screenshot/pdf на віддаленій машині")
    extra_args: List[str] = Field(default_factory=list)

# ─────────────────────────────────────────────
# Хелпери
# ─────────────────────────────────────────────
def _http_500(detail: str) -> HTTPException:
    log.exception(detail)
    return HTTPException(status_code=500, detail=detail)


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@lru_cache(maxsize=1)
def get_proxmox() -> ProxmoxAPI:
    """
    Створює та кешує клієнт ProxmoxAPI.
    ENV:
      PROXMOX_HOST=192.168.1.140
      PROXMOX_PORT=8006
      PROXMOX_USER=root@pam
      PROXMOX_TOKEN_NAME=...
      PROXMOX_TOKEN_VALUE=...
      PROXMOX_PASSWORD=... (не бажано)
      PROXMOX_VERIFY_SSL=false | VERIFY_SSL=false
    """
    host = os.getenv("PROXMOX_HOST")
    user = os.getenv("PROXMOX_USER")  # типово "root@pam"
    realm = os.getenv("PROXMOX_REALM", "pam")
    token_name = os.getenv("PROXMOX_TOKEN_NAME")
    token_value = os.getenv("PROXMOX_TOKEN_VALUE")
    password = os.getenv("PROXMOX_PASSWORD")
    verify_ssl = _bool_env("PROXMOX_VERIFY_SSL", _bool_env("VERIFY_SSL", False))
    port = int(os.getenv("PROXMOX_PORT", "8006"))

    if not host:
        raise RuntimeError("Missing PROXMOX_HOST")
    if not user:
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


def _default_node(prox: ProxmoxAPI, node: Optional[str]) -> str:
    if node:
        return node
    nodes = [n["node"] for n in prox.nodes.get()]
    if not nodes:
        raise HTTPException(500, "No Proxmox nodes available")
    return nodes[0]


def _ssh_pct_list() -> List[Dict[str, Any]]:
    """
    Список LXC напряму з Proxmox-хоста через SSH:
      pct list --output-format json
    Потрібні ENV: PVE_SSH_HOST, PVE_SSH_USER, PVE_SSH_KEY_PATH.
    """
    host = os.getenv("PVE_SSH_HOST")
    user = os.getenv("PVE_SSH_USER", "root")
    key = os.getenv("PVE_SSH_KEY_PATH", "/keys/pve_id_rsa")
    if not host:
        raise RuntimeError("PVE_SSH_HOST is not configured")
    cmd = ["ssh", "-i", key, f"{user}@{host}", "pct list --output-format json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        raise RuntimeError(f"SSH/pct call failed: {e}")
    if res.returncode != 0:
        raise RuntimeError(f"pct list rc={res.returncode}: {res.stderr or res.stdout}")
    try:
        return json.loads(res.stdout)
    except Exception:
        raise RuntimeError(f"Unexpected pct output: {res.stdout!r}")


# ─────────────────────────────────────────────
# SSH runner (universal)
# ─────────────────────────────────────────────
class SSHError(RuntimeError):
    pass


class SSHRunner:
    def __init__(
        self,
        host: str,
        user: str = "root",
        port: int = 22,
        key_path: Optional[str] = None,
        key_data_b64: Optional[str] = None,
        password: Optional[str] = None,
        strict_host_key: bool = False,
        timeout: int = 30,
    ):
        self.host = host.split(":")[0] if ":" in host else host
        self.port = port
        self.user = user
        self.key_path = key_path
        self.key_data_b64 = key_data_b64
        self.password = password
        self.strict_host_key = strict_host_key
        self.timeout = timeout

    @staticmethod
    def _load_pkey_from_data(text: str) -> paramiko.PKey:
        excs = []
        for loader in (paramiko.Ed25519Key.from_private_key,
                       paramiko.RSAKey.from_private_key,
                       paramiko.ECDSAKey.from_private_key):
            try:
                return loader(file_obj=StringIO(text))
            except Exception as e:
                excs.append(e)
        raise SSHError(f"Unsupported private key (Ed25519/RSA/ECDSA). Errors: {excs}")

    @staticmethod
    def _load_pkey_from_path(path: str) -> paramiko.PKey:
        excs = []
        for loader in (paramiko.Ed25519Key.from_private_key_file,
                       paramiko.RSAKey.from_private_key_file,
                       paramiko.ECDSAKey.from_private_key_file):
            try:
                return loader(path)
            except Exception as e:
                excs.append(e)
        raise SSHError(f"Unsupported key at {path} (Ed25519/RSA/ECDSA). Errors: {excs}")

    def _get_pkey(self) -> Optional[paramiko.PKey]:
        if self.key_path:
            return self._load_pkey_from_path(self.key_path)
        if self.key_data_b64:
            try:
                text = json.loads(self.key_data_b64)  # якщо випадково передали JSON-рядок
            except Exception:
                text = self.key_data_b64
            try:
                # якщо це base64 (без BEGIN), декодуємо
                if "BEGIN " not in text:
                    import base64
                    text = base64.b64decode(text).decode("utf-8")
            except Exception:
                pass
            return self._load_pkey_from_data(text)
        return None

    def run(self, cmd: str, timeout: int = 900, env: Optional[Dict[str, str]] = None, cwd: Optional[str] = None) -> Tuple[int, str, str]:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(
            paramiko.RejectPolicy() if self.strict_host_key else paramiko.AutoAddPolicy()
        )
        try:
            pkey = self._get_pkey()
            client.connect(
                self.host, port=self.port, username=self.user,
                pkey=pkey, password=self.password if not pkey else None,
                timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout
            )
            full_cmd = cmd
            if env:
                exports = " ".join(f'{k}={shlex.quote(v)}' for k, v in env.items())
                full_cmd = f"{exports} {full_cmd}"
            if cwd:
                full_cmd = f"cd {shlex.quote(cwd)} && {full_cmd}"
            stdin, stdout, stderr = client.exec_command(full_cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore")
            err = stderr.read().decode("utf-8", errors="ignore")
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except Exception as e:
            raise SSHError(str(e))
        finally:
            client.close()


# ─────────────────────────────────────────────
# Ендпойнти: загальні
# ─────────────────────────────────────────────
@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok", "version": app.version}


# ─────────────────────────────────────────────
# Proxmox: LXC
# ─────────────────────────────────────────────
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
def list_lxc(node: Optional[str] = Query(None, description="Назва вузла (наприклад, 'pve'). Якщо не вказано — візьмемо перший.")) -> List[Dict[str, Any]]:
    try:
        prox = get_proxmox()
        node_name = _default_node(prox, node)
        return prox.nodes(node_name).lxc.get()
    except Exception as e:
        raise _http_500(f"/lxc failed: {e}")


@app.get("/lxc-list")
def lxc_list_via_ssh() -> List[Dict[str, Any]]:
    try:
        return _ssh_pct_list()
    except Exception as e:
        raise _http_500(f"/lxc-list failed: {e}")


@app.post("/lxc/start")
def start_lxc(req: StartStopReq) -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        node_name = _default_node(prox, req.node)
        res = prox.nodes(node_name).lxc(req.vmid).status.start.post()
        return {"ok": True, "task": res}
    except Exception as e:
        raise _http_500(f"/lxc/start failed: {e}")


@app.post("/lxc/stop")
def stop_lxc(req: StartStopReq, force: bool = Query(False, description="True — форсована зупинка")) -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        node_name = _default_node(prox, req.node)
        if force:
            res = prox.nodes(node_name).lxc(req.vmid).status.stop.post(force=1)
        else:
            res = prox.nodes(node_name).lxc(req.vmid).status.shutdown.post()
        return {"ok": True, "task": res}
    except Exception as e:
        raise _http_500(f"/lxc/stop failed: {e}")


@app.post("/lxc/create")
def create_lxc(req: CreateLXCReq) -> Dict[str, Any]:
    try:
        prox = get_proxmox()
        node_name = _default_node(prox, req.node)

        payload: Dict[str, Any] = {
            "vmid": req.vmid,
            "hostname": req.hostname,
            "cores": req.cores,
            "memory": req.memory,
            "ostemplate": req.ostemplate,
            "storage": req.storage,
            "rootfs": f"{req.storage}:{req.rootfs_gb}",
            "unprivileged": int(req.unprivileged),
            "start": int(req.start),
        }

        net0 = f"name=eth0,bridge={req.bridge}"
        if req.ip_cidr:
            net0 += f",ip={req.ip_cidr}"
            if req.gateway:
                net0 += f",gw={req.gateway}"
        payload["net0"] = net0

        if req.ssh_public_key:
            payload["ssh-public-keys"] = req.ssh_public_key
        if req.password:
            payload["password"] = req.password

        if req.features:
            payload["features"] = {k: bool(v) for k, v in req.features.items()}

        task = prox.nodes(node_name).lxc.post(**payload)
        return {"created": True, "task": task, "vmid": req.vmid, "node": node_name}
    except Exception as e:
        raise _http_500(f"/lxc/create failed: {e}")


@app.post("/lxc/exec")
def lxc_exec(spec: LXCExecSpec) -> Dict[str, Any]:
    host = os.getenv("PVE_SSH_HOST")
    user = os.getenv("PVE_SSH_USER", "root")
    key = os.getenv("PVE_SSH_KEY_PATH", "/keys/pve_id_rsa")
    if not host:
        raise _http_500("PVE_SSH_HOST is not configured")

    cmd = f"pct exec {spec.vmid} -- bash -lc {shlex.quote(spec.cmd)}"
    try:
        res = subprocess.run(["ssh", "-i", key, f"{user}@{host}", cmd],
                             capture_output=True, text=True, timeout=3600)
        return {"rc": res.returncode, "stdout": res.stdout, "stderr": res.stderr}
    except Exception as e:
        raise _http_500(f"/lxc/exec failed: {e}")


# ─────────────────────────────────────────────
# Deploy у LXC (через pct exec по SSH)
# ─────────────────────────────────────────────
@app.post("/deploy")
def deploy(spec: DeploySpec) -> Dict[str, Any]:
    host = os.getenv("PVE_SSH_HOST")
    user = os.getenv("PVE_SSH_USER", "root")
    key = os.getenv("PVE_SSH_KEY_PATH", "/keys/pve_id_rsa")
    if not host:
        raise _http_500("PVE_SSH_HOST is not configured")

    ctx = {"repo_url": spec.repo_url, "workdir": spec.workdir}
    def render(c: str) -> str:
        out = c
        for k, v in ctx.items():
            out = out.replace("{{"+k+"}}", shlex.quote(v))
        return out

    steps: List[Dict[str, Any]] = []
    commands = [*spec.setup, *spec.commands]
    for c in commands:
        inner = render(c)
        pct_cmd = f"pct exec {spec.target_vmid} -- bash -lc {shlex.quote(inner)}"
        try:
            res = subprocess.run(["ssh", "-i", key, f"{user}@{host}", pct_cmd],
                                 capture_output=True, text=True, timeout=3600)
            steps.append({"cmd": inner, "rc": res.returncode, "stdout": res.stdout, "stderr": res.stderr})
            if res.returncode != 0:
                return {"ok": False, "steps": steps}
        except Exception as e:
            steps.append({"cmd": inner, "rc": -1, "stdout": "", "stderr": str(e)})
            return {"ok": False, "steps": steps}
    return {"ok": True, "steps": steps}


# ─────────────────────────────────────────────
# Універсальний SSH: виконання команд на будь-якому сервері
# ─────────────────────────────────────────────
@app.post("/ssh/run")
def ssh_run(spec: SSHSpec) -> Dict[str, Any]:
    runner = SSHRunner(
        host=spec.host, user=spec.user, port=spec.port,
        key_path=spec.key_path, key_data_b64=spec.key_data_b64, password=spec.password,
        strict_host_key=spec.strict_host_key
    )
    try:
        rc, out, err = runner.run(spec.cmd, env=spec.env, cwd=spec.cwd, timeout=1800)
        return {"rc": rc, "stdout": out, "stderr": err}
    except Exception as e:
        raise _http_500(f"/ssh/run failed: {e}")


# ─────────────────────────────────────────────
# Запуск програм на віддаленому сервері
# ─────────────────────────────────────────────
@app.post("/apps/launch")
def apps_launch(spec: AppLaunchSpec) -> Dict[str, Any]:
    runner = SSHRunner(
        host=spec.host, user=spec.user, port=spec.port,
        key_path=spec.key_path, key_data_b64=spec.key_data_b64, password=spec.password,
        strict_host_key=spec.strict_host_key
    )
    env = dict(spec.env or {})
    if spec.display:
        env["DISPLAY"] = spec.display

    prog = shlex.quote(spec.program)
    args = " ".join(shlex.quote(a) for a in spec.args)
    base_cmd = f"{prog} {args}".strip()

    if spec.background:
        log_file = f"/tmp/{os.path.basename(spec.program)}.log"
        cmd = f"nohup {base_cmd} >{shlex.quote(log_file)} 2>&1 & echo $!"
    else:
        cmd = base_cmd

    try:
        rc, out, err = runner.run(cmd, env=env, cwd=spec.cwd, timeout=120)
        return {"rc": rc, "stdout": out, "stderr": err}
    except Exception as e:
        raise _http_500(f"/apps/launch failed: {e}")


# ─────────────────────────────────────────────
# Віддалений браузер (headless або GUI)
# ─────────────────────────────────────────────
@app.post("/browser/open")
def browser_open(spec: BrowserSpec) -> Dict[str, Any]:
    runner = SSHRunner(
        host=spec.host, user=spec.user, port=spec.port,
        key_path=spec.key_path, key_data_b64=spec.key_data_b64, password=spec.password,
        strict_host_key=spec.strict_host_key
    )

    def build_headless_cmd(bin_name: str) -> str:
        flags = [
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-gpu",
            "--disable-software-rasterizer",
            "--disable-dev-shm-usage",
            f"--window-size={spec.window_size}",
        ]
        if spec.user_data_dir:
            flags.append(f"--user-data-dir={shlex.quote(spec.user_data_dir)}")
        flags += spec.extra_args

        if spec.action == "open":
            return " ".join([shlex.quote(bin_name), "--headless=new", *flags, shlex.quote(spec.url)])
        if spec.action == "screenshot":
            outp = spec.output_path or "/tmp/screenshot.png"
            return " ".join([shlex.quote(bin_name), "--headless=new", *flags, f"--screenshot={shlex.quote(outp)}", shlex.quote(spec.url)])
        if spec.action == "pdf":
            outp = spec.output_path or "/tmp/page.pdf"
            return " ".join([shlex.quote(bin_name), "--headless=new", *flags, f"--print-to-pdf={shlex.quote(outp)}", shlex.quote(spec.url)])
        raise HTTPException(400, f"Unsupported action: {spec.action}")

    # headless
    if spec.headless:
        for candidate in spec.browser_cmds:
            check = f"command -v {shlex.quote(candidate)} >/dev/null 2>&1"
            rc, _, _ = runner.run(check, timeout=10)
            if rc == 0:
                cmd = build_headless_cmd(candidate)
                rc2, out2, err2 = runner.run(cmd, timeout=180)
                return {"rc": rc2, "stdout": out2, "stderr": err2, "used": candidate}
        raise _http_500(f"No browser found from list: {spec.browser_cmds}")

    # GUI (DISPLAY має бути налаштований на віддаленій машині)
    env = {}
    if os.getenv("DEFAULT_GUI_DISPLAY"):
        env["DISPLAY"] = os.getenv("DEFAULT_GUI_DISPLAY")

    # xdg-open спроба
    rc, out, err = runner.run(f"xdg-open {shlex.quote(spec.url)} >/dev/null 2>&1 & echo $!", timeout=10, env=env)
    if rc == 0:
        return {"rc": rc, "stdout": out, "stderr": err, "used": "xdg-open"}

    # fallback: firefox/chrome без headless
    for candidate in ["firefox"] + spec.browser_cmds:
        check = f"command -v {shlex.quote(candidate)} >/dev/null 2>&1"
        rc2, _, _ = runner.run(check, timeout=10, env=env)
        if rc2 == 0:
            cmd = f"{shlex.quote(candidate)} {shlex.quote(spec.url)}"
            rc3, out3, err3 = runner.run(cmd, timeout=30, env=env)
            return {"rc": rc3, "stdout": out3, "stderr": err3, "used": candidate}
    raise _http_500("No GUI browser found (tried xdg-open, firefox, chrome/chromium).")


# ─────────────────────────────────────────────
# Uvicorn launcher (локальний запуск/дебаг)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
