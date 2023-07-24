import nmap
import csv

def results_format(results):
    lines = results.strip().split('\n')
    
    header = lines[0].split(';')
    data = [line.split(';') for line in lines[1:]]
    
    print('Results:')
    for row in data:
        print('-' * 30)
        for i in range(len(header)):
            print(f"{header[i]}: {row[i]}")
            
def scanner_nmap(ip_addr,port,types):
    scanner = nmap.PortScanner()

    if types == '1':
        print('\nNmap Version: ', scanner.nmap_version())
        scanner.scan(ip_addr,port,'-v -sS')
        print(scanner.scaninfo())
        status = scanner[ip_addr].state()
        if status == 'up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            print('Open ports: ',scanner[ip_addr]['tcp'].keys())
            results = scanner.csv().replace('\r','')
            
            results_format(results)
        else:
            print('IP status: ', status)

    elif types == '2':
        print('\nNmap Version: ',scanner.nmap_version())
        scanner.scan(ip_addr,port,'-v -sU')
        print(scanner.scaninfo())
        status = scanner[ip_addr].state()
        if status =='up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            print('Open ports: ',scanner[ip_addr]['udp'].keys())
            results = scanner.csv().replace('\r','')
            
            results_format(results)
        else:
            print('IP status: ', status)

    elif types == '3':
        print('\nNmap Version: ', scanner.nmap_version())
        scanner.scan(ip_addr,port,'-v -sS -sC -sV -A -O')
        print(scanner.scaninfo())
        status == scanner[ip_addr].state()
        if status == 'up':
            print('IP status: ', status)
            print(scanner[ip_addr].all_protocols())
            print('Open ports: ',scanner[ip_addr]['tcp'].keys())
            results = scanner.csv().replace('\r','')
            
            results_format(results)
        else:
            print('IP status: ', status)
            
    elif types >= '4':
        print('Your type not available!! Please, try again!!')


if __name__ == "__main__":
    print('\t\tWelcome to Nmap')
    print('<---------------------------------------------->')

    ip_addr = input('Press IP: ')
    print('==> IP target: ', ip_addr)
    type(ip_addr)

    port = input('Press ports: ')
    if not port.isdigit() or int(port) <= 0 or int(port) > 65535:
        print('==> Invalid port. Using default port range: 1-1024')
        port = '1-1024'
    else:
        print('==> Ports target: ',port)
    type(port)
    
    types = input('''\nSelect type scan:
                    1. SYN ACK 
                    2. UDP 
                    3. Comprehensive
Select: ''')
    
    scanner_nmap(ip_addr,port,types)