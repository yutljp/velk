package main

//go:noinline
func add(a int, b int) int { return a + b }

//go:noinline
func twice(x int) int { return add(x, x) }

func main() { println(twice(21)) }
