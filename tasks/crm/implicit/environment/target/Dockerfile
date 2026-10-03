FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY app.py /srv/app.py
EXPOSE 8080
CMD ["python3", "/srv/app.py"]
