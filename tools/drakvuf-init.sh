#
# Define in /etc/default/drakvuf the following variables:
# VLANS=<number of active VLANs>
# ORIGIN=<master xen vm to be cloned>
# CONFIG=<xen config of master vm>
# SNAPSHOT=<snapshot of master vm to be cloned>
# INJECTPID=<PID of the target process to use in injection>
#
VLANS=$1
ORIGIN=$2
CONFIG=$3
SNAPSHOT=$4

echo "Network Setup"
/home/simone/labs/drakvuf/tools/network-setup-disable.sh
/home/simone/labs/drakvuf/tools/network-setup.sh $VLANS

xl domid $ORIGIN
if [ $? -eq 0 ]
then
    echo "Destroy Windows Master VM"
    xl destroy $ORIGIN
fi

echo "Create Windows Master VM"
xl restore -p -e $CONFIG $SNAPSHOT
