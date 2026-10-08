#!/bin/sh
# Back up the SSH config before reimaging this machine.
mkdir -p /mnt/backup/ssh
cp "${HOME}/.ssh/id_ed25519" /mnt/backup/ssh/
cp "${HOME}/.ssh/config" /mnt/backup/ssh/
chmod 600 /mnt/backup/ssh/*
