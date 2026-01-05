package main

func main() {
	cfg := config{
		addr: ":3000",
	}

	app := application{cfg}
	app.run(app.mount())
}
