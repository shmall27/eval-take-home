FROM python:3.12-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY dispatcher.c /src/dispatcher.c
RUN mkdir -p /out \
    && gcc -O2 -Wall -no-pie -o /out/dispatcher dispatcher.c

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY boundary_eval/ /app/boundary_eval/
COPY --from=build /out/dispatcher /app/bin/dispatcher
COPY dispatcher.c /app/dispatcher.c
COPY app.py /app/app.py
CMD ["python3", "-B", "/app/app.py"]
