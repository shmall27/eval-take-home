FROM python:3.12-slim-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY recordparser.c /src/recordparser.c
RUN gcc -O2 -Wall -o /out/flawed recordparser.c \
    && gcc -O2 -Wall -DRECORDPARSER_PATCHED -o /out/patched recordparser.c

FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY boundary_eval/ /app/boundary_eval/
COPY --from=build /out/flawed /app/bin/flawed
COPY --from=build /out/patched /app/bin/patched
COPY recordparser.c /app/recordparser.c
COPY app.py /app/app.py
CMD ["python3", "-B", "/app/app.py"]
