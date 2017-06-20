rule Gafgyt_Generic_Botnet {
meta:
description = "Gafgyt Generic Botnet Malware Signature"
author = "James Bower"
reference = "Quantum Honeynet"
date = "2017/06/14"
super_rule = 1
hash0 = "2a18f2d59f172622e76d9d9b5c73393b"
hash1 = "06de2d19862494be7dbcbcf20b3dbe3a"
hash2 = "0fc30a802a07386f5cd4b18b47547979"
hash3 = "be6865ccb948f2937fd25fe465e434da"
hash4 = "c8d58acfe524a09d4df7ffbe4a43c429"
hash5 = "0f979b4ae1209020dd2b672f9dad7398"
hash6 = "45826c129bf3d3bd067e33cf7bef3883"
hash7 = "79b9d4cea7972951efad765406459f5e"
hash8 = "baad702930571c414b0e8896f8bb4a5f"
hash9 = "11754a20e705dccf96f1a1def7220efc"
hash10 = "67db9ed04d3b56f966a739fd40a47748"
strings:
$s0 = "busybox" fullword
$s1 = "PONG!" fullword
$s2 = "GETLOCALIP" fullword
$s3 = "HTTPFLOOD" fullword
$s4 = "LUCKYLILDUDE" fullword
$s5 = "/dev/null"
$s6 = "/etc/resolv.conf"
$s7 = "/etc/config/resolv.conf"
condition:
all of them
}
