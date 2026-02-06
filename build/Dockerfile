FROM cgr.dev/chainguard/static:latest
ENV LOG_LEVEL=warn
ENV METRICS_PORT=2112

COPY trivyops /app/trivyops

EXPOSE ${METRICS_PORT}


ENTRYPOINT [ "/app/trivyops", "-d"]