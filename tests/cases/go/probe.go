// L7 — Go: names from pclntab and recovery of typical Go function bodies.
// Expected: names include the package; division, range and type switches are readable.
package main

//go:noinline
func add(a, b int) int { return a + b }

//go:noinline
func divmod(a, b int) (int, int) { return a / b, a % b }

//go:noinline
func sumSlice(xs []int) int {
	s := 0
	for _, v := range xs {
		s += v
	}
	return s
}

//go:noinline
func kindName(x any) int {
	switch x.(type) {
	case int:
		return 1
	case string:
		return 2
	}
	return 0
}

func main() {
	q, r := divmod(7, 3)
	println(sumSlice([]int{1, 2, 3}), add(1, 2), q, r)
	println(kindName(1))
}
