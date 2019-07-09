#Path to Kernel Files
KERNEL_DIR = /lib/modules/$(shell uname -r)/build

obj-m += syscall_hooking.o
syscall_hooking-objs := hooking.o stub_execve.o
EXTRA_CFLAGS += -I$(PWD)/include

all:
	$(MAKE) -C $(KERNEL_DIR) M="$(PWD)" modules
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
