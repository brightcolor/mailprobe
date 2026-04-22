APP=mailprobe

.PHONY: build run test compose-up compose-down

build:
	go build -o bin/$(APP) ./cmd/mailprobe

run:
	go run ./cmd/mailprobe

test:
	go test ./...

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down
