obj-m := firewall.o
firewall-objs := FWRuleDevice.o hw4secws.o FWLogDevice.o PacketHandler.o FWConnectionDevice.o FWProxyDevice.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
