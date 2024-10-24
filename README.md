# Network-Scanner
A Python script and Lib that scans a network for connected devices.

## Setup

Download this repository and run it locally,

```bash
python3 network_scanner_script.py -t ip_address
or
python3 network_scanner_script.py --target ip_address
```
where ip_address is the IP Address of the target machine. Example: 10.0.2.1

The script also accepts a range of ip addresses to be scanned for. For that in the ip_address field you need to provide the range. Example: 10.0.2.1/24
This tells the script that start scanning from 10.0.2.1 to 10.0.2.254

Also you can use scan, find_device_by_mac and display_result functions in your project. 
To use these functions just add following lines to your project.

```python
from network_scanner import find_device_by_mac, scan, display_result

result = scan("192.168.1.1/24")
display_result(result)

device = find_device_by_mac("00:0b:29:8e:4f:5c", "192.168.1.2/24")
```
## Output

#### Output of the Script for a single target IP Address

```bash
root@kali:~/Desktop/Network Scanner# python3 network_scanner.py -t 10.0.2.3
-----------------------------------
IP Address	MAC Address
-----------------------------------
10.0.2.3	  08:00:27:24:58:5a
```

**OR**
```bash
root@kali:~/Desktop/Network Scanner# python3 network_scanner.py --target 10.0.2.3
-----------------------------------
IP Address	MAC Address
-----------------------------------
10.0.2.3	  08:00:27:24:58:5a
```


#### Output of the Script for a range of target IP Address

```bash
root@kali:~/Desktop/Network Scanner# python3 network_scanner.py --target 10.0.2.1/24
-----------------------------------
IP Address	MAC Address
-----------------------------------
10.0.2.1	  52:54:00:12:35:00
10.0.2.2	  52:54:00:12:35:00
10.0.2.15	  08:00:27:e6:e5:59
10.0.2.3	  08:00:27:24:58:5a
```


