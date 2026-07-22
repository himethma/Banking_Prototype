FROM python:3.13-alpine
WORKDIR /lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && adduser -D -u 10001 lab
COPY app.py .
USER 10001
EXPOSE 8081
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8081"]

