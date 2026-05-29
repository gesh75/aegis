# AEGIS community core — sim-tier PreFlight server. Self-contained, zero external deps.
FROM python:3.11-slim

WORKDIR /app

# deps first for layer caching
COPY requirements.txt /app/aegis/requirements.txt
RUN pip install --no-cache-dir -r /app/aegis/requirements.txt

# the package
COPY . /app/aegis

EXPOSE 8088
ENV AEGIS_PORT=8088
# run as the package so `import aegis.*` resolves from /app
CMD ["python", "-m", "aegis.serve"]
