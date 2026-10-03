FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates util-linux passwd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home formworker
WORKDIR /app
COPY boundary_eval/ /app/boundary_eval/
COPY app.py /app/app.py
COPY import_worker.py /app/import_worker.py
CMD ["python3", "-B", "/app/app.py"]
