DB_URL=postgresql://root:Anandadimmas,123@localhost:5432/simple_bank?sslmode=disable

.PHONY: build run clean migrateup migratedown sqlc

build:
	go build -o belajargolang main.go

run: build
	./belajargolang

clean:
	rm -f belajargolang

migrateup:
	migrate -path db/migration -database "$(DB_URL)" -verbose up

migratedown:
	migrate -path db/migration -database "$(DB_URL)" -verbose down

server:
	go run main.go

# sqlc:
# 	sqlc generate -f sqlc.yaml
