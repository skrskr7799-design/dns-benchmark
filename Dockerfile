FROM node:22-bookworm-slim AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/tsconfig.json web/index.html ./
COPY web/src ./src
RUN npm run build

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m app && mkdir /data && chown app:app /data
COPY app.py index.html resolvers.txt ./
COPY backend ./backend
COPY --from=frontend /web/dist ./web-dist
USER app
ENV DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).close()"
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080","--no-proxy-headers"]
