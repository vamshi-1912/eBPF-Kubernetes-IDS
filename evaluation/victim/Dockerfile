# Target workload for the live evaluation: a small web app plus the everyday
# tools (curl, wget, netcat, procps) that real attackers abuse after gaining a shell.
FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl wget netcat-traditional procps iproute2 \
    && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir gunicorn==23.0.0
WORKDIR /app
COPY app.py config.json ./
EXPOSE 8080
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "app:app"]
