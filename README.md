# CS468 HW2 – Docker, Networking, and ARP Spoofing

This repository packages the starter environment for HW2. It uses Docker and docker-compose to stand up a small lab where a client repeatedly hits a Flask server and a third container performs ARP spoofing and packet capture. Use this README as a guide to build, run, and gather the evidence the assignment asks for.

## Prerequisites
- POSIX shell (macOS/Linux or WSL2).
- Docker CLI and docker-compose installed; on macOS you can pair them with Colima (`brew install colima docker docker-compose`).
- Ability to run privileged containers (needed for raw sockets/tcpdump).

## Repository Layout
- `docker-compose.yml`: Defines the bridge network `hwnet` (172.28.0.0/16) and three services (`server-a`, `client-b`, `sniff`). Note the static IPs/MACs and volume mounts (captures and sniff scripts).
- `Dockerfile.server`: Python 3.11 Flask app served on port 80 (`flaskapp/app.py` and `flaskapp/requirements.txt`).
- `Dockerfile.client`: Ubuntu 22.04 with curl/nmap/iproute2 and tcpdump. Entry point (`client_entrypoint.sh`) starts tcpdump before handing control to `script.sh`.
- `Dockerfile.sniff`: Python 3.11 with Scapy and tcpdump; intended for your ARP spoofing tools in `/opt/sniff/scripts`.
- `script.sh`: The client’s loop that posts JSON creds to the server and periodically flushes ARP (`ip -s neigh flush all`).
- `scripts/spoof.py`: Scapy-based bi-directional ARP poisoner (reactive + periodic) that targets client ↔ server.
- `captures/`: Sample pcaps (e.g., `pre-attack.pcap`, `arp-attack.pcap`) written by the client container.

## Bringing Up the Lab
```sh
# from repo root
docker-compose up --build -d
docker ps -a           # verify server, client, sniff are running
```
- The client writes pcaps to `./captures` (host volume). Override iface if needed: `docker compose up -d client-b -e IFACE=eth0`.
- Enter containers as needed: `docker exec -it client sh`, `docker exec -it server sh`, `docker exec -it sniff sh`.

## Captures and Tasks
- **Pre-attack capture (T7):** Start the stack fresh; the client’s entrypoint auto-runs tcpdump. Let it run long enough to record traffic, then stop containers and copy the latest pcap from `captures/` as `pre-attack.pcap`.
- **ARP spoofing (T8):** In the `sniff` container, run `python /opt/sniff/scripts/spoof.py --iface eth0` (adjust iface if different). The script will learn real MACs, poison both directions, and keep running until interrupted.
- **Attack capture (T9):** While spoofing is active, keep the client running so tcpdump captures poisoned traffic. Stop when done and save the resulting file as `arp-attack.pcap` (already written under `captures/`).

## Answering the Short Questions
- Base images, endpoints, credentials, and network details are all visible in the Dockerfiles, compose file, and `script.sh`/`flaskapp/app.py`. Use `docker inspect`, `ip -br a`, `arp -an`, and `docker network inspect` to confirm runtime values.
- The ARP flush in `script.sh` is there to clear neighbor cache entries during the loop; consider how that interacts with spoofing.
- The client posts JSON to the Flask server; inspect `script.sh` and `flaskapp/app.py` to note the endpoint and payload.

## Cleanup
```sh
docker-compose down
docker volume prune -f   # optional if you created volumes
```

Document your findings in `assignment.txt` as required and keep the pcaps under `captures/`.***
