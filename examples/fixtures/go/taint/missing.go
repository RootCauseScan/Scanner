package main

func other() string {
	return "safe"
}

func sink(data string) {
}

func main() {
	x := other()
	sink(x)
}
