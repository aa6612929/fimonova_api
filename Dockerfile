# Use official Python 3.11 slim image
FROM python:3.11-slim

# Avoid python buffering (helps logs)
ENV PYTHONUNBUFFERED=1

# Create app dir
WORKDIR /app

# System deps for psycopg2
RUN apt-get update \
  && apt-get install -y build-essential libpq-dev gcc --no-install-recommends \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy app
COPY . /app

# Create logs dir
RUN mkdir -p /app/logs

# Expose port (Render expects 10000 or default; we'll use 10000)
EXPOSE 10000

# Start command
CMD ["uvicorn", "api_server_minimal:app", "--host", "0.0.0.0", "--port", "10000"]
