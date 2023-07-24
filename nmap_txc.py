import nmap
import csv

scanner = nmap.PortScanner()

print('Welcome to Nmap')
print('<---------------------------------------------->')

ip_addr = input('Press IP: ')
print('==> IP target: ', ip_addr)
type(ip_addr)

port = input('Press ports: ')
if not port.isdigit() or int(port) <= 0:
    print('Invalid port. Using default port range: 1-1024')
    port = '1-1024'
else:
    print('==> Ports target: ',port)
type(port)

def results_format(results):
    lines = results.strip().split('\n')
    
    header = lines[0].split(';')
    data = [line.split(';') for line in lines[1:]]
    
    print('Results:')
    for row in data:
        print('-' * 30)
        for i in range(len(header)):
            print(f"{header[i]}: {row[i]}")

types = input('''\nSelect type scan:
                1. SYN ACK 
                2. UDP 
                3. Comprehensive
Select: ''')

if types == '1':
    print('Nmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr,port,'-v -sS')
    print(scanner.scaninfo())
    print('IP status: ', scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ',scanner[ip_addr]['tcp'].keys())
    results = scanner.csv().replace('\r','')
    
    results_format(results)

elif types == '2':
    print('Nmap Version: ',scanner.nmap_version())
    scanner.scan(ip_addr,port,'-v -sU')
    print(scanner.scaninfo())
    print('IP status: ',scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print('Open ports: ',scanner[ip_addr]['udp'].keys())
    results = scanner.csv().replace('\r','')
    
    results_format(results)

elif types == '3':
    print('\nNmap Version: ', scanner.nmap_version())
    scanner.scan(ip_addr,port,'-v -sS -sC -sV -A -O')
    print(scanner.scaninfo())
    ipsta = print('IP status: ', scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    results = scanner.csv().replace('\r','')
    
    results_format(results)

                
