# TSA Server image (independent). No database inside.
# Build FROM THE PROJECT ROOT (needs the shared common/ package):
#   docker build -f tsa_server/Dockerfile -t im-tsa-server .
#
# Config DEFAULTS ship in tsa_server/variable_config.json; override via env /
# ConfigMap. Needs the CA reachable at startup (IM_CA_URL). MySQL is external.
FROM python:3.10-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUTF8=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY common/     ./common/
COPY tsa_server/ ./tsa_server/

EXPOSE 9002
CMD ["uvicorn", "tsa_server.main:app", "--host", "0.0.0.0", "--port", "9002"]
