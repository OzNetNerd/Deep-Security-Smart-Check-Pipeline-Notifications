FROM python:3.7-alpine

WORKDIR /code
ADD . /code
RUN pip install --no-cache-dir -r requirements.txt
VOLUME ["/tmp"]
CMD ["python", "./run.py"]