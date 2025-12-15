package bpf

//go:generate go tool bpf2go -tags linux Helloringbuffer hello-ring-buffer.c
