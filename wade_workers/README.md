# WADE Worker Bundle

This archive contains the WADE worker framework, queue runner, and sample systemd units.
Copy to `/opt/wade/WADE/`, then enable the service:

```bash
sudo cp -r WADE /opt/wade/
sudo systemctl enable --now wade-queue@autopsy.service
sudo systemctl enable --now wade-queue.timer
```
