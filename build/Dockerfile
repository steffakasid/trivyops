FROM golang:1.18-alpine

RUN user add -m trivyops

USER trivyops

WORKDIR /app

ENV LOG_LEVEL=warn
ENV METRICS_PORT=2112

COPY dist/container_linux_amd64/trivyops /app/trivyops

EXPOSE ${METRICS_PORT}

RUN chmod +x trivyops

ENTRYPOINT [ "trivyops", "-d"]