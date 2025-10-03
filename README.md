# cbw-cac (Configuration-as-Code) — Release Bundle

This release contains:
- `cbw-cac-installer.sh` — installer (v1.1.1)
- `cbw_cac_daemon.py` — daemon (installed to `/etc/cbw-cac/`)
- `cbw_cac_common.sh` — shared shell helpers
- `cbw-cac.conf` — default config
- `cbw-cac.service` — systemd unit file
- `Makefile` — convenience make targets
- `cbw-cacctl` — control CLI (installed to `/usr/local/bin/` by installer)
- `stacks/` — drop compose files here to be auto-added to cloud-init

## Deploy key (recommended)
To allow `chezmoi` to clone a private repo, create a read-only deploy key:

```
sudo mkdir -p /etc/cbw-cac/ssh && sudo chmod 700 /etc/cbw-cac/ssh
sudo ssh-keygen -t ed25519 -f /etc/cbw-cac/ssh/cbw_cac_deploy -N "" -C "cbw-cac deploy key"
sudo chmod 600 /etc/cbw-cac/ssh/cbw_cac_deploy
sudo cat /etc/cbw-cac/ssh/cbw_cac_deploy.pub
# -> add this public key as a Deploy key (read-only) in GitHub repo settings
sudo ssh-keyscan github.com | sudo tee /etc/cbw-cac/known_hosts
sudo chmod 644 /etc/cbw-cac/known_hosts
```

Then edit `/etc/cbw-cac/cbw-cac.conf`:
```
CHEZMOI_REPO_URL=git@github.com:cbwinslow/dotfiles.git
CHEZMOI_BRANCH=main
CHEZMOI_SSH_KEY=/etc/cbw-cac/ssh/cbw_cac_deploy
CHEZMOI_KNOWN_HOSTS=/etc/cbw-cac/known_hosts
```

Restart the service:
```
sudo systemctl restart cbw-cac
```

## Packaging
Run `make package` to produce `cbw-cac-release.zip`.
