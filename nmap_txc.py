import nmap
import csv

def target_port():
    ports = input('Press ports: ')
    if ',' in ports:
        port_list = ports.split(',')
        for port in port_list:
            if not port.isdigit() or int(port) <= 0 or int(port) > 65535:
                print('==> Invalid port. Using default port range: 1-1024')
                ports = '1-1024'
                return ports
        print('==> Target Port: ',ports)
        type(ports)
        return ports
    elif '-' in ports:
        port_list = ports.split('-')
        for port in port_list:
            if not port.isdigit() or int(port) <= 0 or int(port) > 65535:
                print('==> Invalid port. Using default port range: 1-1024')
                ports = '1-1024'
                return ports
        print('==> Target Port: ',ports)
        type(ports)
        return ports
    else:
        if not ports.isdigit() or int(ports) <= 0 or int(ports) > 65535:
            print('==> Invalid port. Using default port range: 1-1024')
            ports = '1-1024'
            return ports
        print('==> Target Port: ',ports)
        type(ports)
        return ports

def replace_IP1(ip_addr,i):
    octet = ip_addr.split('.')
    if len(octet) == 4:
        octet[-1] = str(i)
        new_ip = ".".join(octet)
        return new_ip
    else:
        return None
    
def replace_IP2(ip_addr,x,y):
    octet = ip_addr.split('.')
    if len(octet) == 4:
        octet[-1] = str(x)
        octet[-2] = str(y)
        new_ip = ".".join(octet)
        return new_ip
    else:
        return None

def results_format(results):
    lines = results.strip().split('\n')
    
    header = lines[0].split(';')
    data = [line.split(';') for line in lines[1:]]
    
    print('Results:')
    for row in data:
        print('-' * 30)
        for i in range(len(header)):
            print(f"{header[i]}: {row[i]}")
            
def scanner_an_ip(ip_addr,port,types):
    scanner = nmap.PortScanner()
    vers = scanner.nmap_version()

    if types == '1':
        print('\nNmap Version: %s.%d' % (vers[0],vers[1]))
        scanner.scan(ip_addr,port,'-v -sS')
        print(scanner.scaninfo())
        status = scanner[ip_addr].state()
        if status == 'up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            results = scanner.csv().replace('\r','')
            
            results_format(results)
        else:
            print('IP status: ', status)

    elif types == '2':
        print('\nNmap Version: %s.%d' % (vers[0],vers[1]))
        scanner.scan(ip_addr,port,'-v -sU')
        print(scanner.scaninfo())
        status = scanner[ip_addr].state()
        if status =='up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            results = scanner.csv().replace('\r','')
            
            results_format(results)
        else:
            print('IP status: ', status)

    elif types == '3':
        print('\nNmap Version: %s.%d' % (vers[0],vers[1]))
        scanner.scan(ip_addr,port,'-v -sS -sC -sV -A -O')  
        print(scanner.scaninfo())
        status = scanner[ip_addr].state()
        if status == 'up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            results = scanner.csv().replace('\r','')
            os_match = scanner[ip_addr]['osmatch']
            for match in os_match:
                name_os = match.get('name','')
            print(f'OS: {name_os}')
            
            results_format(results)
        else:
            print('IP status: ', status)
            
    elif types >= '4':
        print('Your type not available!! Please, try again!!')
        
def scanner_ip_range(ip_addr,subnet,ports,types):
    if subnet == '24':
        for i in range (1,255):
            new_ip_addr = replace_IP1(ip_addr,i)
            print("\n<============================================>")
            print("IP: ", new_ip_addr)
            scanner_an_ip(new_ip_addr,ports,types)
        print("<==================== DONE ====================>")
            
    if subnet == '16':
        for i in range (0,256):
            for k in range(1,255):
                new_ip_addr = replace_IP2(ip_addr,k,i)
                print("\n<========================================>")
                print("IP: ",new_ip_addr)
                scanner_an_ip(new_ip_addr,ports,types)
        print("<==================== DONE ====================>")
                        
if __name__ == "__main__":
    print('\t\tWelcome to Nmap')
    print('<---------------------------------------------->')

    type_ip = input('''Select type IP to scan:
                1.An IP address
                2.An Ip address range
Select: ''')
    if type_ip == '1':
        ip_addr = input('Press IP: ')
        print('==> Target IP: ', ip_addr)
        type(ip_addr)
        ports = target_port()
        
        types = input('''\nSelect type scan:
                    1. SYN ACK 
                    2. UDP 
                    3. Comprehensive
Select: ''')
        scanner_an_ip(ip_addr,ports,types)
        
    elif type_ip == '2':
        ip_range = input('Press IP range: ')
        print('==> Target IP range: ', ip_range)
        type(ip_range)
        ports = target_port()
        
        ip_addr = ip_range.split('/')[0]
        subnet = ip_range.split('/')[-1]
        
        types = input('''\nSelect type scan:
                    1. SYN ACK 
                    2. UDP 
                    3. Comprehensive
Select: ''')
        scanner_ip_range(ip_addr,subnet,ports,types)