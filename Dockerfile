FROM python:3.9-alpine

WORKDIR /app

RUN pip install --no-cache-dir pyvmomi prometheus_client

CMD ["python3"]