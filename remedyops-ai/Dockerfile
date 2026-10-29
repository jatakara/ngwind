FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "psycopg[binary]>=3.1,<4"
COPY app.py ssh_diagnostics.py auth_guard.py remediation_safety.py recovery_journal.py process_lock.py atomic_config.py index.html ./
RUN python -c "import auth_guard, remediation_safety, recovery_journal, process_lock, atomic_config"
RUN useradd --uid 10001 --create-home remedyops && mkdir -p /app/.state /app/demo_target && chown -R remedyops:remedyops /app
USER remedyops
EXPOSE 8000
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
