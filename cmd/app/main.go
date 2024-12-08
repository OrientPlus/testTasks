package main

import (
	"fmt"

	"StudyProject/app/server"
)

func main() {
	server, err := server.NewServer()
	if err != nil {
		fmt.Printf("The server could not be started: %s\n", err.Error())
		return
	}

	err = server.Run()
	if err != nil {
		fmt.Printf("The server could not be started: %s\n", err.Error())
	}
}
