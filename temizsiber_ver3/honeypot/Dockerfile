FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    python3-tk \
    tk \
    tcl \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir customtkinter requests

WORKDIR /app

CMD ["python", "main.py"]