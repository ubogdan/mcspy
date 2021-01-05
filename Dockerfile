FROM golang:latest

RUN apt-get update && apt-get install -y libpcap-dev

WORKDIR /apps/mcspy
COPY . .

RUN go get -d -v ./...
RUN go build -v ./...
