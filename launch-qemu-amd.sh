#!/bin/bash

#QEMU=/opt/qemu-4.2-tencent/bin/qemu-system-x86_64
QEMU=/opt/qemu-tencent-v4.2.0_v2//bin/qemu-system-x86_64

QCOW2=/root/tencent/ubuntu-18.04-100G-viommu.qcow2

DEV_LIST1="\
0000:42:00.0 \
"

#DEV_LIST=$DEV_LIST1

ulimit -S -c unlimited
dmesg -c > /dev/null
dmesg -n8

#########################################
# BINDING

modprobe -r vfio-pci 
modprobe -r kvm_amd

for i in $DEV_LIST
do 
	DEVID=`lspci -n -s $i| awk -F '[ :]' '{print $5" "$6}'`

	#-----------------------------------
	# Unbind the drivers
	echo "Unbinding ... $i"
	echo $i> "/sys/bus/pci/devices/$i/driver/unbind"
done

modprobe kvm_amd avic=1
#modprobe kvm_amd avic=0
modprobe vfio-pci 

for i in $DEV_LIST
do 
	DEVID=`lspci -n -s $i| awk -F '[ :]' '{print $5" "$6}'`

	# Bind NIC to vfio-pci
	echo "Binding ... vfio-pci $i"
	echo $DEVID > /sys/bus/pci/drivers/vfio-pci/new_id
done

########################################
#-drive file=$QCOW2,if=virtio,id=disk0 \
#-cpu host,x2apic=off,kvm-msi-ext-dest-id=off \
#-smp $1,maxcpus=288 \

ARGS="\
-qmp unix:/tmp/qmp-sock,server=on,wait=off \
-enable-kvm \
-no-hpet \
-smp $1 \
-m 64G \
-cpu host,x2apic=on \
-machine q35,kernel_irqchip=split \
-global kvm-pit.lost_tick_policy=discard \
-device amd-iommu,xtsup=on,intremap=on,pt=off \
-blockdev node-name=drive0,driver=qcow2,file.driver=file,file.filename=$QCOW2 \
-device virtio-blk-pci,num-queues=8,drive=drive0 \
-device e1000,netdev=user.0 -netdev user,id=user.0,hostfwd=tcp::5555-:22 \
-serial mon:stdio \
-nographic \
"

for i in $DEV_LIST
do
	ARGS="$ARGS -device vfio-pci,host=$i"
done

# Start VM
echo Launching QEMU: $ARGS
#numactl --cpunodebind 0 --membind 0 $QEMU $ARGS
#numactl -C 0,1 $QEMU $ARGS
$QEMU $ARGS
