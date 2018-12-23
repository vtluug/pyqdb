FROM tiangolo/uwsgi-nginx-flask:python3.7

RUN rm -rf /app

COPY ./app /app

ENV NGINX_MAX_UPLOAD 1m

ENV LISTEN_PORT 8080

RUN pip install --no-cache-dir -r requirements.txt

VOLUME ["/app/quotes.db"]
