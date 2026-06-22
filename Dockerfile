FROM python:3.13-alpine

# SECURITY: Create non-root user first
RUN adduser --disabled-password --no-create-home nullnode

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY p2p.py protocol.py crypto.py dht.py nat.py ratelimit.py relay.py client.py ./

# Create directories for persistent DHT storage
RUN mkdir -p /home/nullnode/.nullnode && chown -R nullnode:nullnode /home/nullnode

EXPOSE 9001 6881
ENV PYTHONUNBUFFERED=1

# SECURITY: Run as non-root
USER nullnode

ENTRYPOINT [ "python3", "client.py" ]
CMD [ "p2p", "--port", "9001" ]
