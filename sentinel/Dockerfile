FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY sentinel /app/sentinel
RUN mkdir -p /data
EXPOSE 9000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:9000/healthz', timeout=2)"
CMD ["python", "-m", "sentinel.main"]
