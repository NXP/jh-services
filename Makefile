# if KERNELRELEASE is defined, we've been invoked from the
# kernel build system and can use its language.
ifneq (${KERNELRELEASE},)

obj-m := ivshmem.o
ivshmem-y := ivshmem-pci.o ivshmem-pipe.o ivshmem-cbuf.o ivshmem-endpoint.o ivshmem-iovec.o
ivshmem-y += rpmsg-services.o
obj-m += rpmsg-console.o rpmsg-rpc.o

CFLAGS_ivshmem-pci.o := -DIVSHM_V2
CFLAGS_rpmsg-services.o := -I${KDIR}/drivers/rpmsg

# Otherwise we were called directly from the command line.
# Invoke the kernel build system.
else

ifeq (${KDIR},)
$(error KDIR must be set!)
else
PWD := $(shell pwd)
default:
	${MAKE} -C ${KDIR} M=${PWD} modules

modules: default
modules_install: install
install:
	${MAKE} -C ${KDIR} M=${PWD} INSTALL_MOD_PATH=${INSTALL_MOD_PATH} modules_install

clean:
	${MAKE} -C ${KDIR} M=${PWD} clean
endif

endif
