// Package keccak provides Keccak-256 hashing with platform-specific acceleration.
package keccak

import "hash"

const rate = 136 // sponge rate for Keccak-256: (1600 - 2*256) / 8

var _ hash.Hash = (*Hasher)(nil)
