cd bpf
go generate
cd -
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-installsuffix cgo" -o ringbuffgo ./main.go