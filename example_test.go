package keccak_test

import (
	"fmt"

	keccak "github.com/erigontech/fastkeccak"
)

func Example() {
	sum := keccak.Sum256([]byte("hello"))

	var h keccak.Hasher
	h.Write([]byte("hel"))
	h.Write([]byte("lo"))
	streamSum := h.Sum256()

	fmt.Printf("%x\n", sum)
	fmt.Println(sum == streamSum)
	// Output:
	// 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	// true
}
