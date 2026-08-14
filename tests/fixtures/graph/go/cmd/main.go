package main

import (
	"internal/eng"
	_ "internal/side"
	. "internal/dot"
	"github.com/example/external"
)

type LocalType struct{}

func Local() {}

func run() {
	eng.Hello()
	Local()
	var worker eng.Worker
	worker.Run()
	len([]int{})
	LocalType(1)
	panic("boom")
	go Local()
	defer eng.Hello()
	(func() {})()
	_ = external.Value
}
