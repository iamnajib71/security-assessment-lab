FROM projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb AS nuclei
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends nmap smbclient curl iptables python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY templates /templates
COPY scripts/container_scan.py /scanner.py
ENTRYPOINT ["python3", "/scanner.py"]
