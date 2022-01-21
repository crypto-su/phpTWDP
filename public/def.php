<?php
define ("SOL_IP", 0);
if ('Darwin' == PHP_OS){ // macos ise
    define ("IP_TTL", 4);
    system("clear && printf '\e[3J'");
} elseif('Linux' == PHP_OS){ // Linux
    define ("IP_TTL", 2);
    system("clear && printf '\e[3J'");
} else { // windows ise
    define ("IP_TTL", 2);
    system("cls");
}

if (!isset($argv[1]) || $argv[1] == "-h") {
    echo "   Usage: sudo php ".$argv[0]." host or ip\n";
    echo "      -Example: sudo php ".$argv[0]." google.com\n";
    echo "      -Example: sudo php ".$argv[0]." 172.217.20.78\n";
    exit;
} else if (isset($argv[2]) && $argv[2] == "-p" && isset($argv[3])) {
    define("ports", explode(",", $argv[3]));
}