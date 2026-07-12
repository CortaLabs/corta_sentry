package main

import (
	"fmt"
	"github.com/cortalabs/cortasentry/internal/fixtures"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	lab, err := fixtures.Start()
	if err != nil {
		panic(err)
	}
	defer lab.Close()
	fmt.Println(string(lab.JSON()))
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
}
