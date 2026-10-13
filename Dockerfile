FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --home /nonexistent bridge
COPY app.py ops.py admin_ui.py provider_store.py provider_router.py ./
COPY admin/ ./admin/
RUN mkdir -p /data && chown bridge:bridge /data
USER 10001:10001
EXPOSE 8767 8768
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8767", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--no-access-log"]
