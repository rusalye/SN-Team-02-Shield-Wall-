FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
RUN pip install --no-cache-dir streamlit==1.40.0 requests==2.32.3
WORKDIR /app
COPY app.py lab.py /app/
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
