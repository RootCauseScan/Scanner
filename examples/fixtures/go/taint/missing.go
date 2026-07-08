package main

func source() string { return "tainted" }
func sink(s string)  {}
func main() {
	user := source()
	_ = user
	sink("safe")
}
