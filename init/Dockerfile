# One-shot `init` service: generates the secrets on first start (see init-secrets.sh).
FROM alpine:3.20
RUN apk add --no-cache openssh-keygen
COPY init-secrets.sh /init-secrets.sh
RUN chmod 755 /init-secrets.sh
ENTRYPOINT ["/init-secrets.sh"]
