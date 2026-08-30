# Hypercorn brings its own HTTP/2 and, through aioquic, an HTTP/3 stack that
# nothing else in this suite covers - the QUIC implementations here are nginx's
# own, quic-go and quiche.
# Debian rather than Alpine: aioquic ships manylinux wheels but no musl
# ones, so Alpine would compile it from source
FROM python:3.13-slim
RUN pip install --no-cache-dir "hypercorn[h3]==0.17.3"
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 443 8080
CMD ["hypercorn", "--bind", "0.0.0.0:443", "--quic-bind", "0.0.0.0:443", \
     "--certfile", "/conf/cert.pem", "--keyfile", "/conf/key.pem", \
     "--insecure-bind", "0.0.0.0:8080", "app:app"]
