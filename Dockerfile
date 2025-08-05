FROM golang:1.24

WORKDIR /app

COPY bin/backend /app/backend

EXPOSE 80

CMD ["/app/backend"]
