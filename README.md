# ebpf

#Required packages

RHEL/centos/fedora

yum install clang

yum install llvm

ubuntu

apt-get install clang

apt-get install llvm

#compilation:-

clang -I /root/kernel/include/ -I /root/kernel/tools/lib/ -O2 -emit-llvm -c <source file> -o - | llc -march=bpf -filetype=obj -o <output in .o>

# -I is used for header location, so provide headers available in kernel source repo

#To load object file into kernel memory

tc filter add dev eth0  ingress bpf direct-action obj <object file.o> sec <RX section needs to load from source>

#To List object file is successfully loaded

tc filter show dev eth0 ingress

#To list debug logs

tc exec bpf dbg

