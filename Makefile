BINARY_NAME=bin/auth-service

# Стандартные цели
all: build

build:
	mkdir -p bin
	go mod tidy
	go build -o $(BINARY_NAME) ./cmd/app

clean:
	rm -rf bin

run: build
	./$(BINARY_NAME)
