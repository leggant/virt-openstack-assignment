import argparse
import openstack
import getpass
import VM
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

def get_security_groups():
    for port in conn.network.security_groups():
        print(port)

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

def get_current_servers():
    servers = {
        f'{USER}-web': conn.compute.find_server(f'{USER}-web', ignore_missing=True),
        f'{USER}-app': conn.compute.find_server(f'{USER}-app', ignore_missing=True),
        f'{USER}-db': conn.compute.find_server(f'{USER}-db', ignore_missing=True)
    }
    return servers

def delete_network():
    network = get_current_network()
    subnet = get_current_subnet()
    router = get_current_router()
    ports = None
    if(network is not None and subnet is not None):
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
            newvm = conn.compute.add_security_group_to_server(newvm, SYSVAR['security_group'])
            print('created', newvm)
            vmip = conn.network.create_ip(floating_network_id=SYSVAR['border_id'])
            print(vmip)
            newvmip = conn.compute.add_floating_ip_to_server(newvm, vmip.floating_ip_address)
            new_servers.append(newvm)
        else:
            print('VM', VM, 'already exists')
    return new_servers

def delete_current_ips():
    servers = get_current_servers()
    try:
        for VM, server in servers.items():
            if(server is not None):
                xserver = conn.compute.get_server(server.id)
                ip = xserver['addresses'][SYSVAR['net_name']][1]['addr']
                print('\nRemoving IP: ', ip, ' From ', VM)
                try:
                    conn.compute.remove_floating_ip_from_server(xserver, ip)
                    print('IP: ', ip, ' Removed From ', VM)
                except:
                    print('Error removing IP', ip, 'from', VM)
                    continue
                try:
                    netip = conn.network.find_ip(ip)
                    conn.network.delete_ip(netip)
                    print('IP ', ip, ' Removed From The Network', SYSVAR['net_name'], '\n')
                except:
                    print('Error deleting IP ', ip)
                    continue
            else:
                print('No IP Address Assigned To',VM)
    except:
        print('\nAll IPs for', SYSVAR['net_name'], 'have been deleted.\n')


def delete_all_servers():
    current_servers = get_current_servers()
    for server, state in current_servers.items():
        if(state is not None):
            try:
                vm = conn.compute.delete_server(state, ignore_missing=True)
                print(server, 'has been deleted.')
            except:
                print('An Error Occured While Deleting Server: ', server)
        else:
            print(server, 'Has Not Been Created Or Has Been Deleted Already')

def delete_router():
    router = get_current_router()
    if(router is not None):
        try:
            # 1. delete the router interface
            conn.network.remove_interface_from_router(router.id, subnet.id)
        except:
            print('An Error Occured Deleting Interface(s) From Router: ', SYSVAR['router'])
        try:
            # 2. delete the router
            conn.network.delete_router(router.id)
        except:
            print('An Error Occured Deleting Router: ', SYSVAR['router'])

    else:
        print('\nRouter:', SYSVAR['router'], 'Has Already Been Deleted Or Has Not Been Created.')

def create():
    verify_create_keypair()
    create_network()
    new_servers = create_servers()
    pass

def run():
    print(f'Getting Server Data......\n')
    servers = get_current_servers()
    for server_name, server in servers.items():
        res = conn.compute.get_server(server.id)
        if(res.status == "SHUTOFF"):
            print(f'Starting Server: {server_name}\n')
            conn.compute.start_server(server.id)
        else:
            print(f'{server_name} is already running.')
    pass

def stop():
    print(f'Getting Server Data......\n')
    servers = get_current_servers()
    for server_name, server in servers.items():
        res = conn.compute.get_server(server.id)
        if(res.status == "ACTIVE"):
            print(f'Shutting Down Server: {server_name}\n')
            stat = conn.compute.stop_server(server.id)
        else:
            print(f'{server_name} has already been stopped.')
    pass

def destroy():
    # 1. Disassociate and release the floating ip on each server
    delete_current_ips()
    # 2. Delete each server
    delete_all_servers()
    # 3. Delete Router Interface
    # 4. Delete Router
    delete_router()
    # 5. Delete the network and subnet
    delete_network()
    pass

def status():
    intro = '\nCollecting Data for Network: {}.......'
    print(intro.format(SYSVAR['net_name']))
    network = get_current_network()
    if(network is not None):
        netname = network.name
        netstatus = network.status
        print(f'Network Name: \t{netname}\nNetwork Status \t{netstatus}\n')
    else:
        print('\t\033[1;31;40mNetwork Does Not Exist\n')
    intro = '\n\033[1;37;40mCollecting Data for Router: {}.......'
    print(intro.format(SYSVAR['router']))
    router = get_current_router()
    if(router is not None):
        rname = router.name
        rstatus = router.status
        public_ip = router.external_gateway_info['external_fixed_ips'][0]['ip_address']
        zone = router.availability_zones[0]
        routerstat = f'Router Name \t{rname}\nRouter Status: \t{rstatus}\nPublic IP \t{public_ip}\nZone: \t{zone}\n'
        print(routerstat)
    else:
        print('\t\033[1;31;40mRouter Does Not Exist\n')
    print('\033[1;37;40mCollecting Server Data.......')
    allserver = get_current_servers()
    if(allserver is not None):
        for server_name, xserver in allserver.items():
            if(xserver is not None):
                res = conn.compute.get_server(xserver.id)
                groups = res.security_groups
                group_list = ''
                for group in groups:
                    group_list = group_list + group['name'] + ' '
                status = res.status
                key = res.key_name
                region = res.location.region_name
                public_ip = res['addresses'][SYSVAR['net_name']][1]['addr']
                public_ip_type = res['addresses'][SYSVAR['net_name']][1]['OS-EXT-IPS:type']
                private_ip = res['addresses'][SYSVAR['net_name']][0]['addr']
                private_ip_type = res['addresses'][SYSVAR['net_name']][0]['OS-EXT-IPS:type']
                serverstat = f'Server: \t{server_name}\nStatus: \t{status}\nPublic IP: \t{public_ip}\nIP Type: \t{public_ip_type}\nPrivate IP:\t{private_ip}\nIP Type: \t{private_ip_type}\nKey Name: \t{key}\nRegion Zone: \t{region}\nSecurity Groups:\n\t\t{group_list}' 
                print(serverstat, '\n')
            else:
                print(f'\t\033[1;31;40mServer {server_name} Does Not Exist')
    print('\033[1;37;40m')
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
