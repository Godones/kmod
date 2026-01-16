obj-m += hello.o

# remove _mcount section
ccflags-remove-y += -pg
ccflags-remove-y += -fpatchable-function-entry=%

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
        strip -g  hello.ko

clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean