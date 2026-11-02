# Hardened Pentesting Sandbox Executor for PoC verification
FROM alpine:3.20

# Install minimal networking, curl, and python3 tools with clean cache
RUN apk add --no-cache \
    bash \
    curl \
    python3 \
    ca-certificates \
    bind-tools \
    iputils \
    jq \
    && rm -rf /var/cache/apk/* /tmp/*

# Create unprivileged runner user
RUN addgroup -S pentest && adduser -S pentest -G pentest -u 1000 -D

# Set restricted workspace
WORKDIR /sandbox
RUN chown -R pentest:pentest /sandbox

USER pentest

CMD ["/bin/bash"]
