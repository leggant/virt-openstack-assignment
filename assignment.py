import argparse
import openstack
import getpass
openstack.enable_logging()
conn = openstack.connect(cloud_name='openstack', region_name='nz-hlz-1')

IMAGE='ubuntu-minimal-22.04-x86_64'
FLAVOUR='c1.c1r1'
PRIVATE='private-net'
PUBLIC='public-net'
KEYPAIR='openstackkey'
USER='leggtc1'
SECURITYGROUP='assignment2'

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

SYSVAR = {
  "keypair": verify_create_keypair(),
  "image_id": conn.compute.find_image(IMAGE).id,
  "flavour_id": conn.compute.find_flavor(FLAVOUR).id,
  "privatenet_id": conn.network.find_network(PRIVATE).id,
  "border_id": conn.network.find_network(PUBLIC).id,
  "security_group": conn.network.find_security_group(SECURITYGROUP),
  "server_names": [f'{USER}-web', f'{USER}-app',f'{USER}-db'],
  "router": f'{USER}-rtr',
  "net_name": f'{USER}-net',
  "net_addr": '192.168.50.0/24',
  "subnet": f'{USER}-subnet',
  "gateway": '192.168.50.1',
  "ipv": '4',
}

def get_current_network():
    network = conn.network.find_network(SYSVAR['net_name'])
    return network

def get_current_subnet():
    subnet = conn.network.find_subnet(SYSVAR['subnet'])
    return subnet

def get_current_router():
    router = conn.network.find_router(SYSVAR['router'])
    return router

def create_network():
    network = get_current_network()
    subnet = get_current_subnet()
    router = get_current_router()
    if(network is None):
        try:
            network = conn.network.create_network(name=SYSVAR['net_name'])
            print('Network ', SYSVAR['net_name'], ' created')
            print('Network ID: ', network.id, '\n')
        except:
            print('Error: ', SYSVAR['net_name'], ' creation failed')
    if(subnet is None):
        try:
            subnet = conn.network.create_subnet(name=SYSVAR['subnet'], 
            network_id=network.id,ip_version=SYSVAR['ipv'], cidr=SYSVAR['net_addr'], gateway_ip=SYSVAR['gateway']) 
            print('Subnet ', SYSVAR['subnet'], ' created')
            print('Subnet ID: ', subnet.id, '\n')
        except:
            print('Error: ', SYSVAR['subnet'], ' creation failed')
    if(router is None):
        try:
            router = conn.network.create_router(
                name=SYSVAR['router'],external_gateway_info={"network_id": SYSVAR['border_id']})
            print('Router ', SYSVAR['router'], ' created')
            print('Router ID: ', router.id, '\n')
        except:
            print('Error: ', SYSVAR['router'], ' creation failed')
        router = conn.network.add_interface_to_router(router,subnet_id=subnet.id)

def delete_network():
    network = get_current_network()
    subnet = get_current_subnet()
    router = get_current_router()
    ports = conn.network.ports(network_id=network.id,subnet_id=subnet.id,ip_address=SYSVAR['gateway'])
    if(ports is not None):
        for port in ports:
            if(port.fixed_ips[0]['ip_address'] == SYSVAR['gateway']):
                conn.network.remove_interface_from_router(router,subnet_id=subnet.id,port_id=port.id)
    if(subnet is not None):
        conn.network.delete_subnet(subnet, ignore_missing=True)
    if(router is not None):
        conn.network.delete_router(router.id, ignore_missing=True)
    if(network is not None):
        conn.network.delete_network(network, ignore_missing=True)

def get_current_servers():
    servers = {
        f'{USER}-web': conn.compute.find_server(f'{USER}-web', ignore_missing=True),
        f'{USER}-app': conn.compute.find_server(f'{USER}-app', ignore_missing=True),
        f'{USER}-db': conn.compute.find_server(f'{USER}-db', ignore_missing=True)
    }
    return servers

def create_servers():
    network = get_current_network()
    current_servers = get_current_servers()
    subnet = get_current_subnet()
    new_servers = []
    for VM, state in current_servers.items():
        if(state is None):
            print('Creating New Instance of ', VM)
            newvm = conn.compute.create_server(name=VM, image_id=SYSVAR['image_id'], flavor_id=SYSVAR['flavour_id'], networks=[{'uuid': network.id}], 
                key_name=SYSVAR['keypair'].name)
            newvm = conn.compute.wait_for_server(newvm)
            conn.compute.add_security_group_to_server(newvm, SYSVAR['security_group'])
            vmip = conn.network.create_ip(floating_network_id=SYSVAR['border_id'])
            newvmip = conn.compute.add_floating_ip_to_server(newvm, vmip.floating_ip_address)
            new_servers.append(newvm)
        else:
            print('VM ', VM, ' already exists')
    return new_servers

def delete_current_ips():
    servers = get_current_servers()
    try:
        for VM, server in servers.items():
            xserver = conn.compute.get_server(server.id)
            ip = xserver['addresses'][SYSVAR['net_name']][1]['addr']
            print('Removing IP: ', ip, ' From ', VM)
            conn.compute.remove_floating_ip_from_server(xserver, ip)
            print('IP: ', ip, ' Removed From ', VM)
            netip = conn.network.find_ip(ip)
            conn.network.delete_ip(netip)
            print('IP ', ip, ' Removed From The Network', SYSVAR['net_name'], '\n')
    except:
        print('\nAll IPs for', SYSVAR['net_name'], 'have been deleted.\n')
        


def create():
    verify_create_keypair()
    create_network()
    new_servers = create_servers()
    pass

def run():
    ''' Start  a set of Openstack virtual machines
    if they are not already running.
    '''
    pass

def stop():
    ''' Stop  a set of Openstack virtual machines
    if they are running.
    '''
    pass

def destroy():
    current_servers = get_current_servers()
    network = get_current_network()
    router = get_current_router()
    subnet = get_current_subnet()

    # 1. Disassociate and release the floating ip on each server
    delete_current_ips()
    # 2. Delete each server
    for server, state in current_servers.items():
        if(state is not None):
            try:
                vm = conn.compute.delete_server(state)
                print(server, ' has been deleted.')
            except:
                print('An Error Occured While Deleting Server: ', server)
        else:
            print(server, ' Has Not Been Created/Has Been Deleted Already')

    # 3. Delete router/Interface
    if(router is not None):
        try:
            # 3. delete the router interface
            conn.network.remove_interface_from_router(router.id, subnet.id)
            # 4. delete the router
            conn.network.delete_router(router.id)
        except:
            print('An Error Occured Deleting Router: ', SYSVAR['router'])
    else:
        print('Router, ', SYSVAR['router'], ' already delete/not created.')

    # # 5. delete the network
    # if(network is not None):
    #     delete_network()
    # else:
    #     print('No Network For: ', SYSVAR['net_name'])
    pass

def status():
    ''' Print a status report on the OpenStack
    virtual machines created by the create action.
    '''
    pass

### You should not modify anything below this line ###
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', help='One of "create", "run", "stop", "destroy", or "status"')
    args = parser.parse_args()
    operation = args.operation

    operations = {
        'create'  : create,
        'run'     : run,
        'stop'    : stop,
        'destroy' : destroy,
        'status'  : status
        }

    action = operations.get(operation, lambda: print('{}: no such operation'.format(operation)))
    action()
