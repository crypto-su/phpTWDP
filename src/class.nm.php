<?php
require __DIR__.'/../public/def.php';

class Nm {

  public $data;
  public $type;

  function setData($data, $type) {
    $this->data = $data;
    $this->type = $type;
  }

  function iPValid(){
    if (filter_var($this->data[1], FILTER_VALIDATE_IP)) {
        return true;
    } else {
        return false;
    }
  }

  function getIP(){
    if($this->iPValid()){
        $dest_addr = $this->data[1];
    } else {
        $dest_addr = gethostbyname ($this->data[1]);
        if($dest_addr == $this->data[1]){ print "IP address of this domain cannot be resolved: $dest_addr\n"; exit; }
    }
    return $dest_addr;
  }

  function getTraceRoute() {

    $res = array();

    $dest_addr = $this->getIP();

    if($this->type == 'log_on'){
     print "\n".$this->data[1]."\n";
     print "\nTraceroutePhp...\n";
     print "Destination Addr(IP): $dest_addr\n";
    }

    $hops = 32;
    $port = 33434;  // tcp udp port traceroute servisi, unix cihazlar %99.9


    $ttl = 1;
    while ($ttl < $hops) {

        $recv_socket = @socket_create (AF_INET, SOCK_RAW, getprotobyname ('icmp')); // icmp soketi aç
        if (!is_resource($recv_socket)) {
            echo "   Usage: sudo php ".$this->data[0]." ".$this->data[1]."\n\n";
            echo "\n";
            break;
        }
        $send_socket = @socket_create (AF_INET, SOCK_DGRAM, getprotobyname ('udp')); // udp soketi aç

        socket_set_option ($send_socket, SOL_IP, IP_TTL, $ttl); // ttl kaçıncı noktaya kadar gidebilir
        socket_bind ($recv_socket, 0, 0); // soketi var sayılan ip ye ICMP ile bağla. icmp de port gerekmez

        $time1 = microtime (true);

        socket_sendto ($send_socket, "", 0, 0, $dest_addr, $port); // 0 boyutta udp paketi gönder

        $r = array ($recv_socket);
        $w = $e = array ();
        socket_select ($r, $w, $e, 5, 0); // 5 saniye veri alamazsan paketi bırak

        if (count ($r)) {

            socket_recvfrom ($recv_socket, $buf, 512, 0, $recv_addr, $recv_port); // soketteki datadan ip kısmını al

            $time2 = microtime (true);
            $roundtrip = ( $time2 - $time1 ) * 1000; // gidiş dönüş süresi hesapla ms

            if (empty ($recv_addr)) { // ip bulamazsa * göster
                $recv_addr = "*";
                $recv_name = "*";
            } else {
                $recv_name = gethostbyaddr ($recv_addr); // bulursan host alını al. host adı ip döner bunu için ripe, afrinic, pasinic vb ne whois ip yaz
            }

            if($recv_name == $recv_addr){ $recv = '?'; } else { $recv = $recv_name; } // host adı ip ile aynı ise ? yap. whois ip yapılacak RIPE
            if($this->type == 'log_on'){
                printf ("%3d   %-15s  %.3f ms  %s\n", $ttl, $recv_addr, $roundtrip, $recv);
            }
            array_push($res, array('ttl' => $ttl, 'recv_addr' => $recv_addr, 'roundtrip' => $roundtrip, 'recv' => $recv));

        } else {

            if($this->type == 'log_on'){
                printf ("%3d   (timeout)\n", $ttl);
            }

        }

        socket_close ($recv_socket);
        socket_close ($send_socket);
        if ($recv_addr == $dest_addr) break;
        $ttl++;

    }

    print "\nTraceroute hops, INFO Whois RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB...\n";
    $i = 1;
    foreach($res as $key => $value){
        $res[$key]['gsr'] = $this->grs($this->grsCurl($value['recv_addr']));
        printf ("%3d   %-15s  %s\n", $i, $value['recv_addr'], $key!=0 ? $this->pArr($res[$key]['gsr']) : 'modem.home');
        $i++;
    }

    return $res;


  }

  function getDnsRecord() {

    print "\nDNS Records...\n";
    if($this->iPValid()){
        print "\nCannot query dns to ip address!\n";
        return null;
    } else {
       $dnsr = @dns_get_record(rtrim($this->data[1],".").".", DNS_ALL - DNS_PTR);
       if (!$dnsr){
          print "\nCould not resolve this domain DNS!\n";
       }
       $allorr = array('type', 'ip', 'target', 'class', 'ttl', 'mname', 'rname', 'txt', 'ipv6');
       foreach ($dnsr as $key => $value) {
            foreach($value as $kval => $val){
                if(in_array($kval, $allorr)){
                    print "$val - ";
                }
            }
           print "\n";
       }
       return $dnsr;
       // forech printf (if == log_on )
    }

  }

  function portScaner(){

    print "\nPort Scan...\n";
    $portList = array(20,21,22,23,24,25,43,80,81,82,83,8080,443); // örnek portlar. bilinen tüm portları ekle!!!
      if (defined("ports") && count(ports) != 0){
         $portList = array_merge($portList,ports);

      }
      $onPortList = array();
    foreach($portList as $p => $port){
        $connection = @fsockopen($this->getIP(), $port, $errno, $errstr, 1); // porta bakmak için soket aç
        if (is_resource($connection)){
          print "Port: $port => On\n";
          fclose($connection); // açılan bağlantıyı kapat.
          $onPortList[] = $port;
        }
    }
    return $onPortList;

  }

  function grsCurl($gsr){ // RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB

    $url = "http://rest.db.ripe.net/search?source=ripe&source=apnic-grs&source=arin-grs&source=afrinic-grs&source=lacnic-grs&source=jpirr-grs&source=radb-grs&query-string=".$gsr;
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    $headers = array(
       "Accept: application/json",
    );
    curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    $resp = curl_exec($curl);
    curl_close($curl);
    return $resp;

   }

 function grs($data){

    $json = json_decode($data, true);
    $grs = array();
    $infoNegative = array('last-modified','created','remarks','fax-no','phone','person','inetnum','abuse-mailbox','descr');
    foreach ($json['objects']['object'] as $key => $value) {
        foreach($value['attributes']['attribute'] as $k => $v){
            if(!in_array($v['name'], $infoNegative) and $v['value'] != 'NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK'){
                $grs[$v['name']] = $v['value'];
            }

        }
    }
    return $grs;
 }

 function pArr($data){

    $str = "";
    $allorr = array('country','netname','origin','status','admin-c','route');
    foreach($data as $key => $val){
        if(in_array($key, $allorr)){
            $str.= "$val - ";
        }
    }
    return $str;

 }


}