//go:build arm64 && !purego

package keccak

import "testing"

func TestSupportsSHA3(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		detected bool
		want     bool
	}{
		{name: "Darwin", goos: "darwin", want: true},
		{name: "iOS without SHA3", goos: "ios", want: false},
		{name: "Linux with SHA3", goos: "linux", detected: true, want: true},
		{name: "Linux without SHA3", goos: "linux", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportsSHA3(test.goos, test.detected); got != test.want {
				t.Fatalf("supportsSHA3(%q, %t) = %t, want %t", test.goos, test.detected, got, test.want)
			}
		})
	}
}
