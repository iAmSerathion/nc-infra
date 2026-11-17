FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git python3 build-essential pkg-config unzip libatomic1 openssh-client ripgrep xz-utils procps squid && rm -rf /var/lib/apt/lists/*
RUN userdel ubuntu 2>/dev/null || true
RUN useradd --uid 1000 --create-home --shell /bin/bash agent
COPY toolchains /opt/toolchains
COPY claude /usr/local/bin/claude
COPY opencode /usr/local/bin/opencode
COPY entrypoint /usr/local/bin/nc-work-entry
RUN chmod 755 /usr/local/bin/claude /usr/local/bin/opencode /usr/local/bin/nc-work-entry
ENV HOME=/home/agent DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 COREPACK_ENABLE_DOWNLOAD_PROMPT=0
# OpenCode: fixed version, no self-update; model catalog from the bundled snapshot (models.opencode.ai is not allowed).
ENV OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1
USER 1000:1000
COPY --chmod=755 egress /usr/local/bin/nc-egress
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/nc-work-entry"]
CMD ["sleep", "infinity"]
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libnss3 libnspr4 libatk1.0-0t64 libatk-bridge2.0-0t64 libatspi2.0-0t64 libx11-6 libxcomposite1 libxdamage1 libxext6 libxfixes3 libxrandr2 libgbm1 libdrm2 libcups2t64 libasound2t64 libpango-1.0-0 libcairo2 fonts-liberation && rm -rf /var/lib/apt/lists/*
USER 1000:1000
