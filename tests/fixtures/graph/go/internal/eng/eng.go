package eng

func SameSpan() { Missing() }

// café keeps byte-column coverage on a multibyte UTF-8 source file.
type Base interface{}

type Child interface {
	Base
}

type Core struct{}

type Wrapped struct {
	Core
}

func Hello() {}

func (Core) Run() {}
