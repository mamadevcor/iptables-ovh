iptables -t mangle -F 
iptables -t raw -F 
iptables -F 

#--- whitelist ip ---- 
iptables -t mangle -A PREROUTING -s yourip -j ACCEPT 
iptables -t raw -A PREROUTING -s yourip -j ACCEPT 
#--- BLOCK IP --- 
ipset create niggers hash:net maxelem 12288 timeout 10 
iptables -t mangle -A PREROUTING -m set --match-set niggers src -j DROP 
 
#--------------------------------------- RAW AREA -------------------------------------------------------------- 
 
#--- BLOCK PACKET UNNEED 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 2,21 1 0 443,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "15,48 0 0 0,84 0 0 240,21 0 5 96,48 0 0 6,21 8 0 6,21 0 8 44,48 0 0 40,21 5 6 6,48 0 0 0,84 0 0 240,21 0 3 64,48 0 0 9,21 0 1 6,6 0 0 0,6 0 0 65535" -j DROP 
 
#--- PATCH METHODS --- 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 512,6 0 0 65535,6 0 0 0" -j SET --add-set niggers src 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 502,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 5 --hashlimit-name toofastnigger6 -j SET --add-set niggers src 
iptables -t raw -A PREROUTING --match bpf --bytecode "16,48 0 0 0,84 0 0 240,21 0 12 64,48 0 0 9,21 0 10 6,40 0 0 6,69 8 0 8191,177 0 0 0,80 0 0 37,21 0 5 3,80 0 0 38,21 0 3 3,80 0 0 39,21 0 1 7,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 5 --hashlimit-name toofastnigger8 -j SET --add-set niggers src 
iptables -t raw -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 0 3 8,80 0 0 23,21 0 1 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 5 --hashlimit-name toofastnigger2 -j SET --add-set niggers src 
iptables -t raw -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 3 0 8,80 0 0 23,21 1 0 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 5 --hashlimit-name toofastnigger1 -j SET --add-set niggers src 
 
#--- PATCH METHODS --- 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 1460,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 512,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 29512,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,80 0 0 12,21 0 1 80,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "7,48 0 0 0,84 0 0 240,21 0 3 64,40 0 0 2,21 0 1 1500,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 192,6 0 0 65535,6 0 0 0" -j DROP 
 
#--- NON IPSET --- 
iptables -t raw -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 502,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 30/s --hashlimit-burst 3 --hashlimit-name toofastnigger3 -j DROP

iptables -t raw -A PREROUTING --match bpf --bytecode "16,48 0 0 0,84 0 0 240,21 0 12 64,48 0 0 9,21 0 10 6,40 0 0 6,69 8 0 8191,177 0 0 0,80 0 0 37,21 0 5 3,80 0 0 38,21 0 3 3,80 0 0 39,21 0 1 7,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 30/s --hashlimit-burst 3 --hashlimit-name toofastnigger7 -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 0 3 8,80 0 0 23,21 0 1 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 30/s --hashlimit-burst 3 --hashlimit-name toofastnigger4 -j DROP 
iptables -t raw -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 3 0 8,80 0 0 23,21 1 0 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 30/s --hashlimit-burst 3 --hashlimit-name toofastnigger5 -j DROP 
 
 
 
#--------------------------------------- MANGLE AREA ----------------------------------------------------------- 
 
#--- BLOCK PACKET UNNEED 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 2,21 1 0 443,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "15,48 0 0 0,84 0 0 240,21 0 5 96,48 0 0 6,21 8 0 6,21 0 8 44,48 0 0 40,21 5 6 6,48 0 0 0,84 0 0 240,21 0 3 64,48 0 0 9,21 0 1 6,6 0 0 0,6 0 0 65535" -j DROP 
 
#--- PATCH METHODS --- 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 512,6 0 0 65535,6 0 0 0" -j SET --add-set niggers src 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 502,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger6 -j SET --add-set niggers src 
iptables -t mangle -A PREROUTING --match bpf --bytecode "16,48 0 0 0,84 0 0 240,21 0 12 64,48 0 0 9,21 0 10 6,40 0 0 6,69 8 0 8191,177 0 0 0,80 0 0 37,21 0 5 3,80 0 0 38,21 0 3 3,80 0 0 39,21 0 1 7,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger8 -j SET --add-set niggers src 
iptables -t mangle -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 0 3 8,80 0 0 23,21 0 1 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger2 -j SET --add-set niggers src 
iptables -t mangle -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 3 0 8,80 0 0 23,21 1 0 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger1 -j SET --add-set niggers src 
 
#--- PATCH METHODS --- 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 1460,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 512,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 29512,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,80 0 0 12,21 0 1 80,6 0 0 65535,6 0 0 0" -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "7,48 0 0 0,84 0 0 240,21 0 3 64,40 0 0 2,21 0 1 1500,6 0 0 65535,6 0 0 0" -j DROP

iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 192,6 0 0 65535,6 0 0 0" -j DROP 
 
#--- NON IPSET --- 
iptables -t mangle -A PREROUTING --match bpf --bytecode "12,48 0 0 0,84 0 0 240,21 0 8 64,48 0 0 9,21 0 6 6,40 0 0 6,69 4 0 8191,177 0 0 0,72 0 0 14,21 0 1 502,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger3 -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "16,48 0 0 0,84 0 0 240,21 0 12 64,48 0 0 9,21 0 10 6,40 0 0 6,69 8 0 8191,177 0 0 0,80 0 0 37,21 0 5 3,80 0 0 38,21 0 3 3,80 0 0 39,21 0 1 7,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger7 -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 0 3 8,80 0 0 23,21 0 1 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger4 -j DROP 
iptables -t mangle -A PREROUTING --match bpf --bytecode "14,48 0 0 0,84 0 0 240,21 0 10 64,48 0 0 9,21 0 8 6,40 0 0 6,69 6 0 8191,177 0 0 0,80 0 0 22,21 3 0 8,80 0 0 23,21 1 0 10,6 0 0 65535,6 0 0 0" -m hashlimit --hashlimit-mode srcip --hashlimit-above 7/s --hashlimit-burst 3 --hashlimit-name toofastnigger5 -j DROP
