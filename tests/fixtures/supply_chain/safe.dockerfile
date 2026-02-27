# Safe Dockerfile - uses pinned tags
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3

FROM python:3.12-slim
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
