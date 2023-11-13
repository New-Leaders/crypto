FROM python:3.11
LABEL authors="andrewheuneman"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update

RUN mkdir /app
WORKDIR /app

COPY requirements.txt /app
RUN pip install -r requirements.txt

COPY new_leaders_crypto.py .
COPY generate_encryption_keys.py .
COPY main.py .

ENTRYPOINT ["python", "./main.py"]
