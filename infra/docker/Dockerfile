# VULNERABILITY: Running as root
FROM ubuntu:latest

# VULNERABILITY: Hardcoded secrets in Dockerfile
ENV DB_PASSWORD=SuperSecretPassword123!
ENV API_KEY=sk-1234567890abcdef
ENV JWT_SECRET=hardcoded-jwt-secret-docker

# VULNERABILITY: Using ADD instead of COPY with remote URL
ADD https://example.com/app.tar.gz /app/

# VULNERABILITY: Running apt-get upgrade without version pinning
RUN apt-get update && apt-get install -y curl wget openssh-server

# VULNERABILITY: Exposing SSH
EXPOSE 22

# VULNERABILITY: Copying secrets into image
COPY ./secrets/credentials.json /app/credentials.json

WORKDIR /app
COPY . /app

# VULNERABILITY: World-writable directory
RUN chmod 777 /app

# VULNERABILITY: Running as root, no USER instruction
CMD ["python", "app.py"]
