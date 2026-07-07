package main

func source() string {
	return "tainted"
}

func sink(data string) {
}

func main() {
	x := source()
	sink(x)
}
