# Build context: repository root
#   docker build -f services/ebpf-agent/Dockerfile -t ids-agent:latest .

# ---- stage 1: compile the libbpf CO-RE program and the C loader -------------------
FROM debian:bookworm AS bpf-build
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool gcc make libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY services/ebpf-agent/Makefile ./
COPY services/ebpf-agent/bpf ./bpf
COPY services/ebpf-agent/loader ./loader
RUN make

# ---- stage 2: runtime (same Debian release -> same libbpf ABI) --------------------
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libbpf1 libelf1 zlib1g \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/ebpf-agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=bpf-build /src/build/ids_loader /app/ids_loader
COPY ml/model /app/model
COPY services/ebpf-agent/ids_agent /app/ids_agent
COPY services/ebpf-agent/entrypoint.sh /app/entrypoint.sh
ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/app/entrypoint.sh"]
