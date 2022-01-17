<?php
require_once __DIR__.'/src/class.nm.php';

$proc_1 = new Nm();
$proc_1->setData($argv, 'log_on'); // log_on/log_of print realtime data

$arr1 = $proc_1->getTraceRoute(); // Traceroute
//print_r ($arr1); // ALL Data Traceroute Data Array +RIPE, APNIC, ARIN, AFRINIC, LACNIC, JPIRR, RADB

$arr2 = $proc_1->getDnsRecord(); // DNS Records
//print_r ($arr2); // ALL DNS Records Array

$arr3 = $proc_1->portScaner(); // Port Scanner
//print_r ($arr3); // ALL On Ports Array

?>