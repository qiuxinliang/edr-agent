FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libssl3 \
    libcurl4 \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY edr_agent /usr/local/bin/
COPY config/ /etc/edr/config/

RUN useradd -r -s /usr/sbin/nologin edragent
RUN mkdir -p /var/log/edr /var/lib/edr
RUN chown edragent:edragent /var/log/edr /var/lib/edr

USER edragent

ENV EDR_CONFIG_PATH=/etc/edr/config
ENV EDR_LOG_PATH=/var/log/edr
ENV EDR_DATA_PATH=/var/lib/edr

EXPOSE 8080

ENTRYPOINT ["edr_agent"]