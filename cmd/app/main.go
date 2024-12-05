package main

import (
	"fmt"

	"StudyProject/app/server"
)

func main() {
	server, err := server.NewServer()
	if err != nil {
		fmt.Printf("The server could not be started: %s", err.Error())
	}

	server.Run()
}
