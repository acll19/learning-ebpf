# Visualize verifier explored paths
sudo bpftool prog dump xlated name kprobe_exec visual > out.dot;

# Convert to png
# sudo apt install graphviz
dot -Tpng ./out.dot > out.png