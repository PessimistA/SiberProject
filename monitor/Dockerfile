FROM python:3.10-slim

# CustomTkinter ve X11 arayüzü için gerekli sistem kütüphaneleri
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk \
    tcl \
    libx11-6 \
    && rm -rf /var/lib/apt/lists/*

# Gerekli Python kütüphaneleri (Sadece ihtiyaç olanlar)
RUN pip install --no-cache-dir customtkinter requests

WORKDIR /app

# Konteyner ayağa kalktığında main.py çalışacak
CMD ["python", "main.py"]