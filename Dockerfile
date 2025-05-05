FROM python:3.11-slim

WORKDIR /api
COPY . /api

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000
CMD ["python", "api/main.py"]