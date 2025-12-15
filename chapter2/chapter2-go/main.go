package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type value_t struct {
	Counter uint64
	Cmd     [16]int8
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(fmt.Errorf("removing memlock: %w", err))
	}

	spec, err := loadHello()
	if err != nil {
		panic(err)
	}

	var obj helloObjects
	if err := spec.LoadAndAssign(&obj, nil); err != nil {
		panic(err)
	}
	defer obj.Close()

	execveLink, err := link.Kprobe("sys_execve", obj.Hello, &link.KprobeOptions{
		Cookie: 1,
	})
	if err != nil {
		panic(err)
	}
	defer execveLink.Close()

	openactLink, err := link.Kprobe("sys_openat", obj.Hello, &link.KprobeOptions{
		Cookie: 2,
	})
	if err != nil {
		panic(err)
	}
	defer openactLink.Close()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-stop:
			fmt.Println("Exiting...")
			return
		case <-ticker.C:
			fmt.Println("==========================================")
			var s string
			iter := obj.CounterTable.Iterate()
			var key uint64
			var value value_t
			for iter.Next(&key, &value) {
				if len(value.Cmd) == 0 {
					s += fmt.Sprintf("PID %d: %d, openat inkoked\n", key, value.Counter)
				}
				comm := make([]byte, len(value.Cmd))
				for i, b := range value.Cmd {
					comm[i] = byte(b)
				}
				s += fmt.Sprintf("PID %d: %d, %s invoked\n", key, value.Counter, string(comm))
			}
			if err := iter.Err(); err != nil {
				panic(err)
			}
			fmt.Print(s)
		}
	}
}
