#!/bin/bash
# DIAGNOSTIC ONLY - NOT CAPABILITY EVIDENCE. Inert replay of a synthetic event fixture; nothing here was observed from an agent or a real system.
# Oracle step: write the prescribed synthetic submission so the verifier can
# check artifact handoff. This solves nothing; the package has no target.
set -euo pipefail
mkdir -p /app
printf '%s' synthetic-answer-5a62dc3e0940d04e > /app/answer.txt
