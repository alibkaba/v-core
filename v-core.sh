#!/bin/bash
clear

### Preperation ###
# Check if the required files exist

# Community String
if [ -f community ]; then
	continue
else
	echo "[+] Creating the community string"
	echo -e "public\nprivate\ncommunity" > community
fi

# vulscan
if [ -f vulscan.nse ]; then
	continue
else
	echo "[+] Downloading the Vulscan-Script for Nmap.."
	wget http://computec.ch/projekte/vulscan/download/nmap_nse_vulscan-2.0.tar.gz && tar xzf nmap_nse_vulscan-2.0.tar.gz
	wget http://computec.ch/projekte/vulscan/download/scipvuldb.csv
	echo "Done!"
fi

clear



TARGET="10.11.1.21"
FTP="ftp"
SMB="netbios\|smb"
SMTP="smtp"
SNMP="snmp"



### Light Scan ###
echo -e "\n[*] Starting light Scan for $TARGET..."
nmap -p U:161,3389,T:21,22,110,80,443,137-139,445,25,3306,1433,1521,79 $TARGET --open -sV > $TARGET-light.txt
echo "[+] Light scan for $TARGET Done!"

# Grab Domain-Name
echo "[+] Grabbing the Domain-Name for $TARGET & will be saved into $TARGET-domain_name.txt"
cat $TARGET-light.txt | grep "Service Info" | awk -F" " '{print $4}' | sed 's/;/ /g' > $TARGET-domain_name.txt

# Grab Service Names
echo "[+] Grabbing the Service-Names fot $TARGET & will be saved into $TARGET-light_services.txt"
cat $TARGET-light.txt | grep "tcp\|udp" | awk -F" " '{print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11}' > $TARGET-light_services.txt



### Grab the Ports ###

# FTP
if grep -q "ftp" $TARGET-light.txt; then
	nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p21 $TARGET > $TARGET-ftp.txt
fi

# SNMP
if grep -q "snmp" $TARGET-light.txt; then
	echo -e "public\nprivate\ncommunity" > community
	snmpwalk -c public -v1 $TARGET > $TARGET-snmp.txt
	onesixtyone -c community -i $TARGET >> $TARGET-snmp.txt
	nmap -vv -sV -sU -Pn --script=snmp-netstat,snmp-processes $TARGET -p161 >> $TARGET-snmp.txt

	# Windows Services
	snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2 > $TARGET-snmp_services.txt

	# User enumeration
	/usr/share/doc/python-impacket/examples/samrdump.py SNMP $TARGET > $TARGET-snmp_user.txt
	snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25
fi

# HTTP
if grep -q "http" $TARGET-light.txt; then
	nikto -C all $TARGET > $TARGET-http.txt
	uniscan -u http://$TARGET -qweds >> $TARGEt-http.txt
	nmap --script vulscan.nse --script-args=scipvuldb.csv $TARGET > $TARGET-vulscan.txt
fi

# SMTP
if grep -q "smtp" $TARGET-light.txt; then
	nmap --script=smtp-commands,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p25 $TARGET -oN $TARGET-smtp.txt

	# Users
	nmap --script smtp-enum-users $TARGET -p25 > $TARGET-smtp_users.txt
fi

# NetBIOS
if grep -q "netbios-ssn\|microsoft-ds\|smb" $TARGET-light.txt; then
	nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smbv2-enabled.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse $TARGET -p137-139,445 -oN $TARGET-smb.txt
	enum4linux -a $TARGET >> $TARGET-smb.txt

	# Users
	nmap -sSU --script=smb-enum-users $TARGET -p U:137,T:139,445 $TARGET > $TARGET-smb_users.txt
fi

# ORACLE
if grep -q "oracle" $TARGET-light.txt; then
	oscanner -s $TARGET -P 1521 > $TARGET-oracle.txt

	# USER Bruteforce
	nmap --script=oracle-sid-brute,oracle-brute -p1521 $TARGET -oN $TARGET-oracle_users.txt
fi

# MSSQL
if grep -q "mssql" $TARGET_light.txt; then
	nmap -sU --script ms-sql-info $TARGET -p 1433 -oN $TARGET-mssql.txt
fi


### Heavy Scan ###
#for ip in $(cat living_hosts);do
#	nmap --script discover,vuln -sSU -p- $ip -oN $ip_heavy.txt
#done
