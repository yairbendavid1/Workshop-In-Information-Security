obj-m := firewall.o
firewall-objs := FWRuleDevice.o hw3secws.o FWLogDevice.o PakcetHandler.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
