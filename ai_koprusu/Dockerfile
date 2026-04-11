FROM python:3.10-slim

# CustomTkinter ve X11 arayüzü için gerekli sistem kütüphaneleri
WORKDIR /app

# Gerekli Python kütüphaneleri (Sadece ihtiyaç olanlar)
RUN pip install --no-cache-dir flask requests

COPY app.py .

# Konteyner ayağa kalktığında main.py çalışacak
CMD ["python", "app.py"]