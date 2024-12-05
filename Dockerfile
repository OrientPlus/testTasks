FROM golang:1.22
LABEL authors="Gutrov Roman"

WORKDIR /app

COPY . .

EXPOSE 8080

RUN make build

CMD ["./myapp"]


