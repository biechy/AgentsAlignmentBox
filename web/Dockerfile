# Dashboard (web/server.py).
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir "psycopg[binary]==3.2.3" \
 && useradd -m -u 1003 web
COPY server.py /app/
COPY static/ /app/static/
WORKDIR /app
USER web
EXPOSE 4141
CMD ["python3", "/app/server.py"]
