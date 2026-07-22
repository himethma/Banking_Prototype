FROM python:3.13-alpine
WORKDIR /runner
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && adduser -D -u 10001 runner \
 && mkdir /results \
 && chown runner:runner /results
COPY runner.py .
USER 10001
CMD ["python", "runner.py"]

