# Separate verifier image. Built from this tests/ directory; it must own
# /tests/test.sh (Harbor does not upload tests/ in separate mode). Collected
# artifacts re-materialize at their original absolute paths inside this image.
FROM python:3.12-slim-bookworm
COPY . /tests/
