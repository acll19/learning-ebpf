# Trace bpf syscall a user space program does
 [sudo] strace -e bpf <program>

# Update a map content on the fly
# both key and value must be in hex format
# use bpftool map list to find the map_id, key and value sizes in bytes
sudo bpftool map update id <map_id> key [hex] <key in hex> value [hex] <value in hex>
# Example for this program: key 1001 (my user id), value Hi user 1001
# Find user id by running id -u
# Run this whole the program is running to see the change
sudo bpftool map update id <map_id> key hex e9 03 00 00 value hex 48 69 20 75 73 65 72 20 31 30 30 31 21

# (BTF & CO-RE-related) Generate vmlinux.h
# vmlinux defines all kernel data types
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# https://github.com/aquasecurity/btfhub