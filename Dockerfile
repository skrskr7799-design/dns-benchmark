FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m app && mkdir /data && chown app:app /data
COPY app.py index.html resolvers.txt ./
USER app
ENV DATA_DIR=/data
EXPOSE 8080
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8080"]
