# 0. Compile with clang
clang \
    -target bpf \
        -I/usr/include/x86_64-linux-gnu \
        -g \
    -O2 -o <output file with *.o extension> -c <program C source>

# 1. View disassembled code
llvm-objdump -S hello.bpf.o

# 2. Load program
sudo bpftool prog load hello.bpf.o /sys/fs/bpf/hello

# 3. Check if it's loaded
sudo ls /sys/fs/bpf/

# 4. List loaded program
sudo bpftool prog list | grep -A 5 hello

# 5. Show more details of a program
sudo bpftool prog show id <bpf_id> --pretty
sudo bpftool prog show name <program name> --pretty

# 6. View translated code
sudo bpftool prog dump xlated name hello

# 7. View JIT'ed code (works only if there is support for JIT disassembly)
sudo bpftool prog dump jited name hello

# 8. Attach the program
sudo bpftool net attach xdp id <bpf_id> dev <interface>
# For WI-FI interfaces you may get Error: interface xdp attach failed: Invalid argument
# ...or
ip link set dev <interface> xdp obj <program *.o file> sec <section declared with SEC("...") macro>
# to detach
ip link set dev <interface> xdp off

# 9. Inspect attachment (look for the <bpf_id>)
sudo bpftool net show

# ...or
ip link show

# 10. See output of bpf_printk helper function (from all running BPF programs)
sudo bpftool prog tracelog

# 11. See used maps
sudo bpftool map list | grep -A2 <map id>
# You can get the id's from the output of command 5 above

# 12. See the content of a map
sudo bpftool map dump id <map id>

# 13. Detach
sudo bpftool net detach xdp dev <interface>

# 14. Unload
sudo rm /sys/fs/bpf/<program name>