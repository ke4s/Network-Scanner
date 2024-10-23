from network_scanner import find_device_by_mac, scan, display_result


result = scan("192.168.1.1/24")
display_result(result)


device = find_device_by_mac("00:0b:29:8e:4f:5c", "192.168.1.2/24")
if device == None:
    print("Device not found.")
else:
    print("Device found with IP: {}".format(device["ip"]))