package main

import (
	"fmt"

	"github.com/NureddinFarzaliyev/go-auth-api/internal/db"
)

func main() {
	cfg := config{
		addr: ":3000",
	}

	mongoConn, err := db.ConnectMongo("mongodb://localhost:27017/")
	if err != nil {
		fmt.Println(err)
	}
	cfg.db.mongoConn = mongoConn

	app := application{cfg}
	app.run(app.mount())
}
