package main

func source() string {
	return "tainted"
}

func sanitize(data string) string {
	return data
}

func sink(data string) {
}

func main() {
	x := source()
	x = sanitize(x)
	sink(x)
}
