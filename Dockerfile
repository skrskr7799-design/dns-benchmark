FROM node:22-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/tsconfig.json web/index.html ./
COPY web/src ./src
RUN npm run build

FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b
WORKDIR /app
COPY requirements.txt requirements.lock.txt ./
RUN pip install --no-cache-dir pip==26.2.0 && pip install --no-cache-dir -r requirements.txt -c requirements.lock.txt && pip check && useradd -u 10001 -m app && mkdir -m 700 /data && touch /data/.ndc-volume && chown -R app:app /data
COPY app.py index.html resolvers.txt ./
COPY backend ./backend
COPY --from=frontend /web/dist ./web-dist
USER app
ENV DATA_DIR=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).close()"
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080","--no-proxy-headers"]
