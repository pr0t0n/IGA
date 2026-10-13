FROM python:3.13-alpine

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup -S iga && adduser -S -G iga iga
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py connectors.py catalog.py governance.py ./
COPY tests ./tests

RUN mkdir -p /data && chown iga:iga /data
USER iga

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://127.0.0.1:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
