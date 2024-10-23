import scapy.all as scapy

def scan(target):
    '''
    This function scans the given IP address or range and returns the IP and MAC addresses of the devices in the network.
    @param target: IP address or range to scan.
    @return: List of dictionaries containing IP and MAC addresses of the devices in the network.'''
    arp_request = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    except PermissionError:
        print("Please run with root permissions")
        return []
    result = []
    for sent, received in answered_list:
        result.append({'ip': received.psrc, 'mac': received.hwsrc})
    return result

def find_device_by_mac(mac_address : str, target : str):
    '''
    This function finds the device with the given MAC address in the specified network.
    @param mac_address: MAC address to search for.
    @param target: IP address or range to scan.
    @return: Dictionary containing IP and MAC addresses of the device if found, None otherwise.
    '''

    devices = scan(target)
    for device in devices:
        if device['mac'].lower() == mac_address.lower():
            return device
    return None


def display_result(result):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))

