#### Example test.php

```php
require_once __DIR__.'/src/class.nm.php';

$proc_1 = new Nm();
$proc_1->setData($argv, 'log_on'); // log_on/log_of print realtime data

$arr1 = $proc_1->getTraceRoute(); // Traceroute
//print_r ($arr1); // ALL Data Traceroute Data Array +RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB

$arr2 = $proc_1->getDnsRecord(); // DNS Records
//print_r ($arr2); // ALL DNS Records Array

$arr3 = $proc_1->portScaner(); // Port Scanner
//print_r ($arr3); // ALL On Ports Array
```

#### Console Run

```bash
sudo php test.php google.com
'or'
sudo php test.php 142.250.187.142
```

#### Output
Will be listed in order;

Traceroute

Traceroute Jumps in WHOIS GRS (RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB)

DNS Records

open ports
```
google.com

TraceroutePhp...
Destination Addr(IP): 142.250.187.142
  1   192.168.1.1      3.016 ms  modem.home
  2   213.14.0.206     8.722 ms  host-213-14-0-206.reverse.superonline.net
  3   10.36.247.141    10.819 ms  ?
  4   10.40.169.190    11.669 ms  ?
  5   10.36.6.37       12.188 ms  ?
  6   10.40.171.172    10.188 ms  ?
  7   72.14.197.138    20.305 ms  ?
  8   (timeout)
  9   108.170.236.32   37.230 ms  ?
 10   142.251.52.87    22.451 ms  ?
 11   142.250.187.142  24.324 ms  sof02s45-in-f14.1e100.net

Traceroute hops, INFO Whois RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB...
  1   192.168.1.1      modem.home
  2   213.14.0.206     TR-SUPERONLINE-991108 - TR - TK2426-RIPE - ALLOCATED PA - 
  3   10.36.247.141    EU - IANA1-RIPE - ALLOCATED UNSPECIFIED - 
  4   10.40.169.190    EU - IANA1-RIPE - ALLOCATED UNSPECIFIED - 
  5   10.36.6.37       EU - IANA1-RIPE - ALLOCATED UNSPECIFIED - 
  6   10.40.171.172    EU - IANA1-RIPE - ALLOCATED UNSPECIFIED - 
  7   72.14.197.138    GOOGLE - ALLOCATED UNSPECIFIED - EU - IANA1-RIPE - 72.14.197.0/24 - AS15169 - 
  8   108.170.236.32   GOOGLE - ALLOCATED UNSPECIFIED - EU - IANA1-RIPE - 108.170.236.0/24 - AS15169 - 
  9   142.251.52.87    GOOGLE - ALLOCATED UNSPECIFIED - EU - IANA1-RIPE - 142.251.52.0/24 - AS15169 - 
 10   142.250.187.142  GOOGLE - ALLOCATED UNSPECIFIED - EU - IANA1-RIPE - 142.250.187.0/24 - AS15169 - 

DNS Records...
IN - 270 - A - 142.250.187.142 - 
IN - 4502 - NS - ns4.google.com - 
IN - 4502 - NS - ns3.google.com - 
IN - 4502 - NS - ns2.google.com - 
IN - 4502 - NS - ns1.google.com - 
IN - 15 - SOA - ns1.google.com - dns-admin.google.com - 
IN - 229 - MX - aspmx.l.google.com - 
IN - 229 - MX - alt4.aspmx.l.google.com - 
IN - 229 - MX - alt2.aspmx.l.google.com - 
IN - 229 - MX - alt1.aspmx.l.google.com - 
IN - 229 - MX - alt3.aspmx.l.google.com - 
IN - 328 - AAAA - 2a00:1450:4017:80e::200e - 
IN - 4502 - CAA - 

Port Scane...
Port: 80 => On
Port: 443 => On
```

#### NOTE
You don't need to enable print_r $arr lines. The 'log_on' parameter will be instantly printed on your screen.
But you can get more data with print_r $arr . example: whois ip all records.
