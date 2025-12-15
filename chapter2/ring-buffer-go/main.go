package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ring-buffer/bpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type event_t struct {
	Fdf      int64
	Command  [16]byte
	FileName [128]byte
} // no `__attribute__((packed))` needed in Go unless fields are misaligned

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(fmt.Errorf("removing memlock: %w", err))
	}

	spec, err := bpf.LoadHelloringbuffer()
	if err != nil {
		panic(err)
	}

	var obj bpf.HelloringbufferObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Close()

	link, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.HelloRingBuff, &link.TracepointOptions{})
	if err != nil {
		panic(err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(obj.Output)
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	fmt.Println("Waiting for events..")

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				panic(err)
			}

			var evt event_t
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &evt); err != nil {
				panic(err)
			}
			command := strings.TrimRight(string(evt.Command[:]), "\x00")
			filename := strings.TrimRight(string(evt.FileName[:]), "\x00")

			fmt.Printf("Command: %s, FileName: %s, FD: %d\n=========================\n",
				command,
				filename,
				evt.Fdf)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-stop:
		fmt.Println("Exiting...")
		return
	}
}
