FROM python:3.11-slim

RUN pip install --no-cache-dir mitmproxy==11.0.2 "psycopg[binary]==3.2.3" \
 && useradd -m -u 1001 mitm \
 && mkdir -p /data/mitm /ca-public \
 && chown mitm:mitm /data/mitm /ca-public

COPY anthropic_parse.py openai_parse.py identity.py killswitch.py store.py urltag.py obs_addon.py /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

USER mitm
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
