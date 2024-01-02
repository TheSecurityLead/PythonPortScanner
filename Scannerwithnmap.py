import nmap #imports the nmap library

nm = nmap.PortScanner()

target_ip = input ("Please enter the target IP address: ")
scan_options = "-sV -sC scan_results"

nm.scan(target_ip, arguments=scan_options)

for host in nm.all_host():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for protocol in nm[host].all_protocols():
        print("Protocol: %s" % protocol)
        port_info = nm[host][protocol]
        for port, state in port_info.items():
            print("Port: %s\tState: %s" % (port, state))