#!/usr/bin/env bash
# --------------------------------------------------------------------------
# cbw-cac-installer.sh  v1.1.1
# Author: ChatGPT (GPT-5 Thinking) for Blaine "cbwinslow"
# Date: 2025-10-03
# Summary:
#  One-click installer for CBW Configuration-as-Code (CAC).
#  Installs hooks, daemon, systemd unit, and supporting files.
#
#  Supports: apt, snap, pipx, pip --user, flatpak, Homebrew (brew),
#  chezmoi bootstrap (supports private repos via deploy key), and stacks.
#
set -Eeuo pipefail
SCRIPT_NAME="cbw-cac-installer.sh"
VERSION="1.1.1"

INSTALL_ROOT="/etc/cbw-cac"
SYSTEMD_UNIT="/etc/systemd/system/cbw-cac.service"
PROFILE_D_BASH="/etc/profile.d/cbw-cac.sh"
ZSH_RC_D="/etc/zsh/zshrc.d"
ZSH_HOOK="${ZSH_RC_D}/cbw-cac.zsh"
DATA_DIR="/var/lib/cbw-cac"
LOG_DIR="/var/log/cbw-cac"
COMMAND_LOG="${DATA_DIR}/commands.jsonl"
STATE_JSON="${DATA_DIR}/state.json"
CLOUD_INIT_OUT="${INSTALL_ROOT}/cloud-init.yaml"
DAEMON_PY="${INSTALL_ROOT}/cbw_cac_daemon.py"
COMMON_SH="${INSTALL_ROOT}/cbw_cac_common.sh"
CONF_FILE="${INSTALL_ROOT}/cbw-cac.conf"
STACKS_DIR="${INSTALL_ROOT}/stacks"
CTL_BIN="/usr/local/bin/cbw-cacctl"

DRY_RUN=false
VERBOSE=false

log() { echo "[$SCRIPT_NAME] $*"; }
vrb() { $VERBOSE && log "$*" || true; }
run() { $DRY_RUN && { echo "+ $*"; return 0; } || eval "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }

ensure_root() { if [[ ${EUID} -ne 0 ]]; then echo "Please run as root (sudo)"; exit 1; fi }

uninstall() {
  ensure_root
  systemctl stop cbw-cac.service 2>/dev/null || true
  systemctl disable cbw-cac.service 2>/dev/null || true
  rm -f "$SYSTEMD_UNIT" "$PROFILE_D_BASH" "$ZSH_HOOK" "$DAEMON_PY" "$COMMON_SH" "$CTL_BIN" "$CONF_FILE"
  rm -rf "$INSTALL_ROOT"
  systemctl daemon-reload || true
  echo "Uninstalled cbw-cac. Data/logs removed."
}

usage() {
  cat <<USAGE
$SCRIPT_NAME v$VERSION

Usage: sudo $SCRIPT_NAME [--dry-run] [--verbose] [--uninstall]

USAGE
}

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --verbose) VERBOSE=true ;;
    --uninstall) uninstall; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $arg"; usage; exit 1 ;;
  esac
done

ensure_root
need python3
need systemctl

run "mkdir -p '${INSTALL_ROOT}' '${DATA_DIR}' '${LOG_DIR}' '${STACKS_DIR}'"
run "chmod 750 '${INSTALL_ROOT}'"
run "touch '${COMMAND_LOG}'"
run "chmod 640 '${COMMAND_LOG}'"
run "chown root:adm '${COMMAND_LOG}'"
run "touch '${STATE_JSON}'"
run "chmod 640 '${STATE_JSON}'"
run "chown root:adm '${STATE_JSON}'"

# default config
if [[ ! -f "${CONF_FILE}" ]]; then
  cat >"${CONF_FILE}" <<'CONF'
# cbw-cac.conf - configuration for the daemon
# CHEZMOI_REPO_URL=git@github.com:cbwinslow/dotfiles.git
# CHEZMOI_BRANCH=main
# CHEZMOI_SSH_KEY=/etc/cbw-cac/ssh/cbw_cac_deploy
# CHEZMOI_KNOWN_HOSTS=/etc/cbw-cac/known_hosts
# CONTAINER_ENGINE=docker
# STACKS=coolify,dify
CONF
  run "chmod 640 '${CONF_FILE}'"
fi

# shared helpers
cat >"${COMMON_SH}" <<'COMMON'
# Shared helpers for Bash/Zsh hooks
CBW_CAC_DATA_DIR="/var/lib/cbw-cac"
CBW_CAC_LOG_FILE="${CBW_CAC_DATA_DIR}/commands.jsonl"
CBW_CAC_FLOCK_FD=319

cbw_cac_redact() {
  local line="$*"
  line="${line//Authorization: Bearer [^ ]*/Authorization: Bearer ***REDACTED***}"
  line="${line//apikey=[^ &]*/apikey=***REDACTED***}"
  line="${line//api_key=[^ &]*/api_key=***REDACTED***}"
  line="${line//--password [^ ]*/--password ***REDACTED***}"
  line="${line//password=[^ &]*/password=***REDACTED***}"
  line="${line//--token [^ ]*/--token ***REDACTED***}"
  echo "$line"
}

cbw_cac_append_jsonl() {
  local status="$1" ts="$2" user="$3" shell="$4" cwd="$5" cmd="$6"
  [[ -e "${CBW_CAC_LOG_FILE}" ]] || return 0
  local escaped_cmd
  escaped_cmd=$(printf '%s' "$cmd" | sed 's/\\/\\\\/g; s/"/\\"/g')
  local escaped_cwd
  escaped_cwd=$(printf '%s' "$cwd" | sed 's/\\/\\\\/g; s/"/\\"/g')
  local line
  line="{\"ts\":\"$ts\",\"user\":\"$user\",\"shell\":\"$shell\",\"cwd\":\"$escaped_cwd\",\"exit\":$status,\"cmd\":\"$escaped_cmd\"}"
  exec {CBW_CAC_FLOCK_FD}>>"${CBW_CAC_LOG_FILE}"
  flock -x "${CBW_CAC_FLOCK_FD}" bash -c "echo '$line' >> '${CBW_CAC_LOG_FILE}'"
  exec {CBW_CAC_FLOCK_FD}>&-
}
COMMON
run "chmod 644 '${COMMON_SH}'"

# bash hook
cat >"${PROFILE_D_BASH}" <<'BASH'
# cbw-cac bash observer
case $- in *i*) :;; *) return;; esac
if [[ -r /etc/cbw-cac/cbw_cac_common.sh ]]; then . /etc/cbw-cac/cbw_cac_common.sh; fi
__CBW_CAC_LAST_CMD=""
trap '__CBW_CAC_LAST_CMD=${BASH_COMMAND}' DEBUG
__cbw_cac_prompt_logger() {
  local status=$?
  if [[ -n "$__CBW_CAC_LAST_CMD" ]]; then
    if [[ $status -eq 0 ]]; then
      local ts user shell cwd cmd
      ts=$(date --iso-8601=seconds)
      user=$(id -un)
      shell="bash"
      cwd="$PWD"
      cmd=$(cbw_cac_redact "$__CBW_CAC_LAST_CMD")
      cbw_cac_append_jsonl "$status" "$ts" "$user" "$shell" "$cwd" "$cmd"
    fi
    __CBW_CAC_LAST_CMD=""
  fi
}
PROMPT_COMMAND="__cbw_cac_prompt_logger; ${PROMPT_COMMAND:-}"
BASH
run "chmod 644 '${PROFILE_D_BASH}'"

# zsh hook
run "mkdir -p '${ZSH_RC_D}'"
cat >"${ZSH_HOOK}" <<'ZSH'
# cbw-cac zsh observer
if [[ -r /etc/cbw-cac/cbw_cac_common.sh ]]; then . /etc/cbw-cac/cbw_cac_common.sh; fi
typeset -g __CBW_CAC_LAST_CMD=""
function preexec() { __CBW_CAC_LAST_CMD="$1"; }
function precmd() {
  local status=$?
  if [[ -n "$__CBW_CAC_LAST_CMD" && $status -eq 0 ]]; then
    local ts user shell cwd cmd
    ts=$(date --iso-8601=seconds)
    user=$(id -un)
    shell="zsh"
    cwd="$PWD"
    cmd=$(cbw_cac_redact "$__CBW_CAC_LAST_CMD")
    cbw_cac_append_jsonl "$status" "$ts" "$user" "$shell" "$cwd" "$cmd"
  fi
  __CBW_CAC_LAST_CMD=""
}
ZSH
run "chmod 644 '${ZSH_HOOK}'"

# daemon (written into INSTALL_ROOT)
cat >"${DAEMON_PY}" <<'PY'
#!/usr/bin/env python3
# cbw_cac_daemon - v1.1.1 (supports CHEZMOI SSH deploy key)
import json, os, re, sys, time, glob, logging, subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any

DATA_DIR = "/var/lib/cbw-cac"
LOG_DIR = "/var/log/cbw-cac"
COMMAND_LOG = os.path.join(DATA_DIR, "commands.jsonl")
STATE_JSON = os.path.join(DATA_DIR, "state.json")
CLOUD_INIT_OUT = "/etc/cbw-cac/cloud-init.yaml"
CONF_FILE = "/etc/cbw-cac/cbw-cac.conf"
STACKS_DIR = "/etc/cbw-cac/stacks"

SCAN_INTERVAL_SECS = 30 * 60
RENDER_INTERVAL_SECS = 60

os.makedirs(LOG_DIR, exist_ok=True)
logging.basicConfig(filename=os.path.join(LOG_DIR, 'service.log'),
                    level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("cbw-cac")

def run(cmd: List[str], check=False):
    try:
        return subprocess.run(cmd, check=check, text=True, capture_output=True)
    except Exception as e:
        logger.error("run(%s) failed: %s", cmd, e)
        return subprocess.CompletedProcess(cmd, 1, "", str(e))

def load_state():
    if os.path.exists(STATE_JSON):
        try:
            with open(STATE_JSON, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to load state.json: %s", e)
    return {"apt": {"manual": {}}, "snap": {}, "pipx": {}, "pip_user": {}, "flatpak": {"apps": {}, "remotes": {}}, "brew": {"formulae": {}, "casks": {}}, "observed": {"install": [], "remove": []}, "last_render": None, "last_scan": None}

def save_state(state):
    tmp = STATE_JSON + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_JSON)

def parse_conf(path):
    conf = {}
    if not os.path.exists(path):
        return conf
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    k,v = line.split('=',1)
                    conf[k.strip()] = v.strip()
    except Exception as e:
        logger.error("Failed to parse conf: %s", e)
    return conf

APT_INSTALL_RE = re.compile(r"^(?:sudo\s+)?(?:apt|apt-get|aptitude)\s+(-y\s+)?install\s+(.+)$")
APT_REMOVE_RE  = re.compile(r"^(?:sudo\s+)?(?:apt|apt-get|aptitude)\s+(-y\s+)?(remove|purge)\s+(.+)$")
DPKG_INSTALL_RE = re.compile(r"^(?:sudo\s+)?dpkg\s+-i\s+(.+\.deb)\s*$")
SNAP_INSTALL_RE = re.compile(r"^(?:sudo\s+)?snap\s+install\s+(.+)$")
SNAP_REMOVE_RE  = re.compile(r"^(?:sudo\s+)?snap\s+(?:remove|uninstall)\s+(.+)$")
PIPX_INSTALL_RE = re.compile(r"^(?:sudo\s+)?pipx\s+install\s+(.+)$")
PIPX_UNINSTALL_RE = re.compile(r"^(?:sudo\s+)?pipx\s+uninstall\s+(.+)$")
PIP_USER_INSTALL_RE = re.compile(r"^(?:sudo\s+)?pip3?\s+install\s+(?:--user\s+)?(.+)$")
PIP_USER_UNINSTALL_RE = re.compile(r"^(?:sudo\s+)?pip3?\s+uninstall\s+(-y\s+)?(.+)$")
FLATPAK_INSTALL_RE = re.compile(r"^(?:sudo\s+)?flatpak\s+install\s+(.+)$")
FLATPAK_UNINSTALL_RE = re.compile(r"^(?:sudo\s+)?flatpak\s+uninstall\s+(.+)$")
BREW_INSTALL_RE = re.compile(r"^(?:sudo\s+)?brew\s+install\s+(.+)$")
BREW_UNINSTALL_RE = re.compile(r"^(?:sudo\s+)?brew\s+uninstall\s+(.+)$")

def parse_pkg_list(arg_str):
    tokens = arg_str.strip().split()
    pkgs=[]
    for t in tokens:
        if t.startswith('-'): continue
        if t.startswith('http://') or t.startswith('https://'): continue
        pkgs.append(t)
    return pkgs

def has(cmd):
    return run(["bash","-lc",f"command -v {cmd} >/dev/null 2>&1 && echo yes || echo no"]).stdout.strip()=="yes"

def scan_apt_manual():
    out = run(["bash","-lc","apt-mark showmanual || true"]).stdout
    names=[l.strip() for l in out.splitlines() if l.strip()]
    versions={}
    if names:
        q = run(["bash","-lc","dpkg-query -W -f='${Package} ${Version}\\n'"], check=False)
        for line in q.stdout.splitlines():
            try:
                n,v=line.split(maxsplit=1)
                if n in names: versions[n]=v
            except ValueError:
                continue
    return versions

def scan_snaps():
    res={}
    if not has("snap"): return res
    p=run(["snap","list"])
    if p.returncode!=0: return res
    lines=p.stdout.splitlines()[1:]
    for line in lines:
        cols=[c for c in line.split() if c]
        if len(cols)>=4:
            name,version,rev,track=cols[0],cols[1],cols[2],cols[3]
            res[name]={"version":version,"channel":track,"classic":False}
    return res

def scan_pipx():
    res={}
    if not has("pipx"): return res
    p=run(["pipx","list","--json"])
    if p.returncode!=0: return res
    try:
        j=json.loads(p.stdout)
        for venv in j.get("venvs",{}).values():
            pkg=venv.get("metadata",{}).get("main_package",{})
            name=pkg.get("package"); ver=pkg.get("package_version")
            if name and ver: res[name]=ver
    except Exception as e:
        logger.error("pipx parse error: %s", e)
    return res

def scan_pip_user():
    res={}
    if not has("pip3"): return res
    p=run(["bash","-lc","pip3 list --user --format json || true"])
    try:
        arr=json.loads(p.stdout)
        for e in arr:
            name,ver=e.get("name"),e.get("version")
            if name and ver: res[name]=ver
    except Exception:
        pass
    return res

def scan_flatpak():
    res={"apps":{}, "remotes":{}}
    if not has("flatpak"): return res
    r=run(["flatpak","remotes"])
    if r.returncode==0:
        for line in r.stdout.splitlines()[1:]:
            cols=[c for c in line.split() if c]
            if cols: res["remotes"][cols[0]]=True
    a=run(["flatpak","list","--app","--columns","application,branch,origin"])
    if a.returncode==0:
        for line in a.stdout.splitlines():
            cols=[c for c in line.split() if c]
            if len(cols)>=3:
                app,branch,origin=cols[0],cols[1],cols[2]
                res["apps"][app]={"branch":branch,"origin":origin}
    return res

def scan_brew():
    res={"formulae":{}, "casks":{}}
    if not has("brew"): return res
    f=run(["brew","list","--formula","--versions"])
    if f.returncode==0:
        for line in f.stdout.splitlines():
            parts=line.split()
            if parts:
                name=parts[0]; ver=parts[1] if len(parts)>1 else ""
                res["formulae"][name]=ver
    c=run(["brew","list","--cask","--versions"])
    if c.returncode==0:
        for line in c.stdout.splitlines():
            parts=line.split()
            if parts:
                name=parts[0]; ver=parts[1] if len(parts)>1 else ""
                res["casks"][name]=ver
    return res

def render_cloud_init(state, conf):
    lines=[]
    lines.append("#cloud-config")
    lines.append("package_update: true")
    lines.append("package_upgrade: false")
    apt_names=sorted(state.get("apt",{}).get("manual",{}).keys())
    if apt_names:
        lines.append("packages:")
        for n in apt_names:
            lines.append(f"  - {n}")
    else:
        lines.append("packages: []")
    snaps=state.get("snap",{})
    if snaps:
        lines.append("snap:")
        lines.append("  commands:")
        for name,meta in sorted(snaps.items()):
            channel=meta.get("channel","stable"); classic=meta.get("classic",False)
            flag=" --classic" if classic else ""
            lines.append(f"    - snap install {name} --channel={channel}{flag}")
    runcmd=[]
    pipx_pkgs=state.get("pipx",{}); pip_user=state.get("pip_user",{})
    if pipx_pkgs or pip_user:
        runcmd.append('[ bash, -lc, "command -v pipx >/dev/null 2>&1 || (apt-get update && apt-get install -y pipx)" ]')
        for name in sorted(pipx_pkgs.keys()):
            runcmd.append(f'[ bash, -lc, "pipx install {name} || true" ]')
        for name in sorted(pip_user.keys()):
            runcmd.append(f'[ bash, -lc, "pip3 install --user {name} || true" ]')
    flatpak=state.get("flatpak",{})
    if flatpak.get("apps"):
        runcmd.append('[ bash, -lc, "apt-get update && apt-get install -y flatpak||true" ]')
        runcmd.append('[ bash, -lc, "flatpak remotes | grep -q \'^flathub\' || flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo" ]')
        for app,meta in sorted(flatpak.get("apps",{}).items()):
            origin=meta.get("origin","flathub"); branch=meta.get("branch","stable")
            runcmd.append(f'[ bash, -lc, "flatpak install -y {origin} {app} {branch} || true" ]')
    brew=state.get("brew",{})
    if brew.get("formulae") or brew.get("casks"):
        runcmd.append('[ bash, -lc, "command -v brew >/dev/null 2>&1 || /bin/bash -c \\"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\\"" ]')
        runcmd.append('[ bash, -lc, "eval \\"$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)\" || true" ]')
        for name in sorted(brew.get("formulae",{}).keys()):
            runcmd.append(f'[ bash, -lc, "brew install {name} || true" ]')
        for name in sorted(brew.get("casks",{}).keys()):
            runcmd.append(f'[ bash, -lc, "brew install --cask {name} || true" ]')
    chez_url=conf.get("CHEZMOI_REPO_URL"); chez_branch=conf.get("CHEZMOI_BRANCH","")
    if chez_url:
        ssh_key=conf.get("CHEZMOI_SSH_KEY"); known_hosts=conf.get("CHEZMOI_KNOWN_HOSTS","/etc/cbw-cac/known_hosts")
        git_ssh_prefix=""
        if ssh_key:
            git_ssh_prefix = f"GIT_SSH_COMMAND='ssh -i {ssh_key} -o UserKnownHostsFile={known_hosts} -o StrictHostKeyChecking=yes' "
        runcmd.append('[ bash, -lc, "apt-get update && apt-get install -y chezmoi git||true" ]')
        if chez_branch:
            runcmd.append(f'[ bash, -lc, "{git_ssh_prefix}chezmoi init --branch {chez_branch} {chez_url} && chezmoi apply -v" ]')
        else:
            runcmd.append(f'[ bash, -lc, "{git_ssh_prefix}chezmoi init {chez_url} && chezmoi apply -v" ]')
    engine=conf.get("CONTAINER_ENGINE","docker").strip() or "docker"
    stack_files=sorted(glob.glob(os.path.join(STACKS_DIR,"*.yml")))
    if stack_files:
        if engine=="docker":
            runcmd.append('[ bash, -lc, "apt-get update && apt-get install -y docker.io docker-compose-plugin||true" ]')
        else:
            runcmd.append('[ bash, -lc, "apt-get update && apt-get install -y podman podman-compose||true" ]')
        for f in stack_files:
            if engine=="docker":
                runcmd.append(f'[ bash, -lc, "docker compose -f {f} up -d || true" ]')
            else:
                runcmd.append(f'[ bash, -lc, "podman-compose -f {f} up -d || true" ]')
    if runcmd:
        lines.append("runcmd:")
        for item in runcmd:
            lines.append(f"  - {item}")
    return "\n".join(lines)+"\n"

def parse_pkg_list(arg_str):
    return [t for t in arg_str.strip().split() if not t.startswith('-')]

def handle_command(cmd, state):
    changed=False
    m=APT_INSTALL_RE.match(cmd)
    if m:
        pkgs=parse_pkg_list(m.group(2))
        if pkgs:
            q=run(["bash","-lc","dpkg-query -W -f='${Package} ${Version}\\n' "+ " ".join(pkgs)])
            for line in q.stdout.splitlines():
                try:
                    name,ver=line.split(maxsplit=1)
                    if name:
                        state.setdefault("apt",{}).setdefault("manual",{})[name]=ver; changed=True
                except ValueError:
                    continue
        return changed
    m=APT_REMOVE_RE.match(cmd)
    if m:
        pkgs=parse_pkg_list(m.group(3))
        for name in pkgs:
            if name in state.get("apt",{}).get("manual",{}):
                del state["apt"]["manual"][name]; changed=True
        return changed
    if DPKG_INSTALL_RE.match(cmd):
        run(["bash","-lc","apt-get -f install -y || true"])
        state["apt"]["manual"]=scan_apt_manual()
        return True
    m=SNAP_INSTALL_RE.match(cmd)
    if m:
        parts=m.group(1).split(); name=parts[0]; classic="--classic" in parts; channel="stable"
        for p in parts[1:]:
            if p.startswith("--channel="): channel=p.split("=",1)[1]
        snaps=scan_snaps()
        meta=snaps.get(name,{"version":"","channel":channel,"classic":classic})
        state.setdefault("snap",{})[name]=meta; return True
    m=SNAP_REMOVE_RE.match(cmd)
    if m:
        name=m.group(1).split()[0]
        if name in state.get("snap",{}): del state["snap"][name]; return True
        return False
    if PIPX_INSTALL_RE.match(cmd) or PIPX_UNINSTALL_RE.match(cmd):
        state["pipx"]=scan_pipx(); return True
    if PIP_USER_INSTALL_RE.match(cmd) or PIP_USER_UNINSTALL_RE.match(cmd):
        state["pip_user"]=scan_pip_user(); return True
    m=FLATPAK_INSTALL_RE.match(cmd)
    if m:
        state["flatpak"]=scan_flatpak(); return True
    m=FLATPAK_UNINSTALL_RE.match(cmd)
    if m:
        state["flatpak"]=scan_flatpak(); return True
    if BREW_INSTALL_RE.match(cmd) or BREW_UNINSTALL_RE.match(cmd):
        state["brew"]=scan_brew(); return True
    return False

def follow_file(path):
    while not os.path.exists(path): time.sleep(1)
    with open(path,'r',encoding='utf-8') as f:
        f.seek(0,os.SEEK_END)
        while True:
            pos=f.tell(); line=f.readline()
            if not line:
                time.sleep(0.5); f.seek(pos)
            else:
                yield line.rstrip('\n')

def full_scan(state):
    changed=False
    try:
        apt_manual=scan_apt_manual()
        if apt_manual!=state.get("apt",{}).get("manual",{}):
            state.setdefault("apt",{})["manual"]=apt_manual; changed=True
    except Exception as e:
        logger.error("APT scan failed: %s", e)
    try:
        snaps=scan_snaps()
        if snaps!=state.get("snap",{}):
            state["snap"]=snaps; changed=True
    except Exception as e:
        logger.error("Snap scan failed: %s", e)
    try:
        pipx_pkgs=scan_pipx()
        if pipx_pkgs!=state.get("pipx",{}):
            state["pipx"]=pipx_pkgs; changed=True
    except Exception as e:
        logger.error("pipx scan failed: %s", e)
    try:
        pip_user=scan_pip_user()
        if pip_user!=state.get("pip_user",{}):
            state["pip_user"]=pip_user; changed=True
    except Exception as e:
        logger.error("pip --user scan failed: %s", e)
    try:
        flat=scan_flatpak()
        if flat!=state.get("flatpak",{}):
            state["flatpak"]=flat; changed=True
    except Exception as e:
        logger.error("flatpak scan failed: %s", e)
    try:
        br=scan_brew()
        if br!=state.get("brew",{}):
            state["brew"]=br; changed=True
    except Exception as e:
        logger.error("brew scan failed: %s", e)
    return changed

def write_cloud_init(state):
    conf=parse_conf(CONF_FILE)
    yaml=render_cloud_init(state,conf)
    tmp=CLOUD_INIT_OUT+".tmp"
    with open(tmp,'w',encoding='utf-8') as f: f.write(yaml)
    os.replace(tmp,CLOUD_INIT_OUT); os.chmod(CLOUD_INIT_OUT,0o600)

def main():
    os.makedirs(os.path.dirname(CLOUD_INIT_OUT),exist_ok=True)
    state=load_state()
    changed=full_scan(state)
    if changed:
        save_state(state); write_cloud_init(state)
        state["last_render"]=datetime.utcnow().isoformat(); save_state(state)
    last_scan=datetime.utcnow(); last_render=datetime.utcnow()-timedelta(seconds=RENDER_INTERVAL_SECS)
    for raw in follow_file(COMMAND_LOG):
        try:
            rec=json.loads(raw)
        except Exception:
            continue
        cmd=rec.get("cmd","")
        if not cmd: continue
        if handle_command(cmd,state):
            now=datetime.utcnow()
            if (now-last_render).total_seconds()>=RENDER_INTERVAL_SECS:
                save_state(state); write_cloud_init(state)
                last_render=now; state["last_render"]=now.isoformat(); save_state(state)
        now=datetime.utcnow()
        if (now-last_scan).total_seconds()>=SCAN_INTERVAL_SECS:
            if full_scan(state):
                save_state(state); write_cloud_init(state)
                last_render=now; state["last_render"]=now.isoformat()
            state["last_scan"]=now.isoformat(); save_state(state)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e: logger.exception("Fatal error: %s", e); sys.exit(1)
PY

run "chmod 755 '${DAEMON_PY}'"

# systemd unit
cat >"${SYSTEMD_UNIT}" <<UNIT
[Unit]
Description=CBW Configuration-as-Code (CAC) Cloud-Init Builder
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=${DAEMON_PY}
Restart=on-failure
RestartSec=5s
User=root
Group=root
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${INSTALL_ROOT} ${DATA_DIR} ${LOG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
run "chmod 644 '${SYSTEMD_UNIT}'"

# ctl
cat >"${CTL_BIN}" <<'CTL'
#!/usr/bin/env bash
set -Eeuo pipefail
CMD=${1:-}
INSTALL_ROOT="/etc/cbw-cac"
DATA_DIR="/var/lib/cbw-cac"
CLOUD_INIT_OUT="${INSTALL_ROOT}/cloud-init.yaml"
CONF_FILE="${INSTALL_ROOT}/cbw-cac.conf"
usage(){ cat <<U
cbw-cacctl — control CLI
Usage:
  cbw-cacctl show
  cbw-cacctl rescan
  cbw-cacctl state
  cbw-cacctl follow
  cbw-cacctl config
U
}
case "$CMD" in
  show) sudo cat "$CLOUD_INIT_OUT" || true ;;
  state) sudo jq . "${DATA_DIR}/state.json" 2>/dev/null || sudo cat "${DATA_DIR}/state.json" ;;
  follow) sudo tail -f "${DATA_DIR}/commands.jsonl" ;;
  rescan) sudo /usr/bin/env python3 - <<'PY'
p="/var/lib/cbw-cac/commands.jsonl"
with open(p,'a',encoding='utf-8') as f: f.write('\n')
print("rescan appended")
PY
  ;;
  config) sudo sed -n '1,200p' "${CONF_FILE}" 2>/dev/null || echo "(no config)" ;;
  *) usage ;;
esac
CTL
run "chmod 755 '${CTL_BIN}'"

run "systemctl daemon-reload"
run "systemctl enable --now cbw-cac.service || true"

log "Installed cbw-cac (v$VERSION)"
log "Cloud-init: ${CLOUD_INIT_OUT}"
log "Commands log: ${COMMAND_LOG}"
log "State JSON: ${STATE_JSON}"
log "Config file: ${CONF_FILE}"
log "Stacks dir: ${STACKS_DIR}"
log "ctl: ${CTL_BIN}"
