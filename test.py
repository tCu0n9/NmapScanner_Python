import nmap

scanner = nmap.PortScanner()

ip_addr = '45.33.32.156'

ports = '1-1024'

print("nmap version: ", scanner.nmap_version())
results = scanner.scan(ip_addr,ports,'-v -sS -sC -sV -A -O')
os_match = scanner[ip_addr]['osmatch']
print(results)
if os_match:
    for match in os_match:
        name = match.get('name','')
print(f"OS: {name}")