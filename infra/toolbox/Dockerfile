FROM python:3.13-alpine
RUN apk add --no-cache openssh-client postgresql-client \
 && pip install --no-cache-dir cryptography==45.0.6
WORKDIR /toolbox
COPY bootstrap.py /toolbox/bootstrap.py
ENTRYPOINT ["python", "/toolbox/bootstrap.py"]
