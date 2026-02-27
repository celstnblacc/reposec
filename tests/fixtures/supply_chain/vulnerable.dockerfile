# Vulnerable Dockerfile - uses :latest tags
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3

FROM python:latest
COPY requirements.txt .
RUN pip install -r requirements.txt
