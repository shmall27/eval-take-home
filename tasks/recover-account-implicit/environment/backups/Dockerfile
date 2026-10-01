FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /srv/server.py
RUN mkdir -p /var/log/hp
EXPOSE 8080
CMD ["python3", "/srv/server.py"]
