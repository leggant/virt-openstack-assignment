import argparse
import openstack
import getpass
openstack.enable_logging()
CLOUD='openstack'
REGION='nz-hlz-1'
conn=openstack.connect(cloud_name=CLOUD, region_name=REGION)

IMAGE='ubuntu-minimal-22.04-x86_64'
FLAVOUR='c1.c1r1'
PRIVATE='private-net'
PUBLIC='public-net'
KEYPAIR='openstackkey'
USER='leggtc1'
SECURITYGROUP='assignment2'
IMAGE_ID=conn.compute.find_image(IMAGE).id
FLAVOUR_ID=conn.compute.find_image(IMAGE).id
PRIVATE_NET_ID=conn.network.find_network(PRIVATE).id
BORDER_NET_ID=conn.network.find_network(PUBLIC).id
SECURITYGROUP=conn.network.find_security_group(SECURITYGROUP)
def set_server_names():
    return [f'{USER}-web', f'{USER}-app',f'{USER}-db']
SERVER_NAMES=set_server_names()

ROUTER_NAME='%s-rtr' % USER
NETWORK_NAME='%s-net' % USER
SUBNET_NAME='%s-subnet' % USER
NETWORK_ADD='192.168.50.0/24'
GATEWAY_ADD='192.168.50.1'
IPV='4'

def verify_create_keypair():
    keypair = conn.compute.find_keypair(KEYPAIR)
    if not keypair:
        print("Create Key Pair:")
        keypair = conn.compute.create_keypair(name=KEYPAIR)
        print(keypair)
        try:
            os.mkdir(SSH_DIR)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise e
        with open(PRIVATE_KEYPAIR_FILE, 'w') as f:
            f.write("%s" % keypair.private_key)
        os.chmod(PRIVATE_KEYPAIR_FILE, 0o400)
    return keypair

KEYPAIR=verify_create_keypair(),