FROM python:3.11-slim

# Imposta la working directory
WORKDIR /app

# Installazione dipendenze di sistema e kubectl
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && \
    \
    K8S_VERSION=$(curl -sL https://dl.k8s.io/release/stable.txt) && \
    echo "Kubectl version: $K8S_VERSION" && \
    curl -LO "https://dl.k8s.io/release/${K8S_VERSION}/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && \
    rm kubectl && \
    apt-get purge -y --auto-remove curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Copia le dipendenze Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia il codice dell'app
COPY main.py .

# Comando di avvio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

