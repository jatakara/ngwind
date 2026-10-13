FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.1,<4"
COPY app.py ssh_diagnostics.py index.html ./
RUN useradd --uid 10001 --create-home remedyops && mkdir -p /app/.state /app/demo_target && chown -R remedyops:remedyops /app
USER remedyops
EXPOSE 8000
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
