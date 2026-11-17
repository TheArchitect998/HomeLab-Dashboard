FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/homelab-dashboard

RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements-dashboard.txt .
RUN pip install --no-cache-dir -r requirements-dashboard.txt \
    && mkdir -p frontend state \
    && chown 10001:10001 state \
    && chmod 700 state

COPY dashboard_api.py .
COPY frontend/index.html frontend/index.html

USER 10001:10001
EXPOSE 8888
CMD ["uvicorn", "dashboard_api:app", "--host", "0.0.0.0", "--port", "8888"]
