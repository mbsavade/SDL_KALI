import nmap
def myscan(host_range ='127.0.0.1', port_range ='1-100'):
    nm = nmap.PortScanner()
    nm.scan(host_range, port_range)
    for host in nm.all_hosts():
        print("Host: " + host + "  |  State: " + nm[host].state())
        for protocol in nm[host].all_protocols():
            if protocol == 'tcp':
                for port in nm[host][protocol].keys():
                    print("Port: " + str(port) + "  |  State: " + str(nm[host][protocol][port]['state']) + "  |  Service: " + str(nm[host][protocol][port]['name']))
if __name__ == "__main__":

    while True:
        host_range = raw_input("\nPress exit to Quit\nEnter host range sample(XX.XX.XX.0-10) or sample(XX.XX.XX.XX): ")
        if host_range == host_range.lower():
            break
        else:
            port_range = raw_input("Enter Port range sample(1-100 or 100): ")
myscan(host_range, port_range)