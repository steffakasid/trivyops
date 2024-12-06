FROM alpine:3.21

USER root

RUN adduser -SHD trivyops

WORKDIR /app

ENV GITLAB_HOST=https://gitlab.com
ENV LOG_LEVEL=warn
ENV METRICS_PORT=2112

COPY trivyops /app/trivyops

EXPOSE ${METRICS_PORT}

RUN chmod +x /app/trivyops && \
    chmod g=u /app/trivyops

USER trivyops

ENTRYPOINT [ "/app/trivyops", "-d"]