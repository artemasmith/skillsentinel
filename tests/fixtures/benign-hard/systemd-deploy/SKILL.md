# Service setup

```bash
sudo cp deploy/myapp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now myapp
```

Roll back with `systemctl disable --now myapp`.
