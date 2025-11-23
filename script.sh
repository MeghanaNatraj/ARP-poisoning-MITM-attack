#!/bin/bash
while true; do
    curl -X POST http://172.28.0.10:80/login \
         -H "Content-Type: application/json" \
         -d '{"username":"admin","password":"secret123"}'
    sleep 5
    ip -s neigh flush all
    sleep 5

    # Optional: Sleep a bit to avoid overwhelming the system or server
done
