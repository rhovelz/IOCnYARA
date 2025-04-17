rule QILIN_ransomware
{
meta:
description = "Detects QILIN ransomware IOCs including binaries, C2 domains, IPs, and email"
strings:
// Suspicious Email
$email = "nopaperplanes@proton.me"
// Remote IPs
$ip1 = "180.131.145.73"
$ip2 = "184.174.96.70"
// C2 Domains (as strings, any variation with subdomains)
$domain1 = "misctoolsupdate.com"
$domain2 = "login.misctoolsupdate.com"
$domain3 = "sso.misctoolsupdate.com"
// Malicious Binaries & CobaltStrike (MD5 as hex patterns)
$md5_1 = { B3 77 FF 70 6F B3 60 06 CD B1 B6 B7 1E 62 B7 E4 }
$md5_2 = { D2 E1 D5 CE 8B 85 D5 E5 F4 21 06 B2 8C 3F 6E 1E }
$md5_3 = { F5 1B 82 D0 BA 1B 46 CF 56 C9 BC C8 21 27 FB 45 }
$md5_4 = { 28 B1 9B 7E 68 9C 33 99 12 79 3F CA 56 27 54 1E }
$md5_5 = { 01 F8 92 41 2F 9A D5 02 7D 6E 8A 19 EC F5 30 FE }
$md5_6 = { D2 AB 39 EA 2C 0F CD 17 27 51 F8 4B DA 72 3A 97 }
$md5_7 = { BE 05 29 FA A5 55 73 6D BF 72 D8 8C B5 0C B3 18 }
$md5_8 = { 52 E6 66 A3 2D 08 47 B4 16 B6 6A D9 AA 98 BB ED }
$md5_9 = { D6 30 63 C5 31 68 E4 EA 82 35 EE E6 5E DE A4 E6 }
$cs_6 = { D1 C4 3F 8D B2 30 BD F1 8C 61 D6 72 44 0E BA 12 }
$cs_7 = { 71 D6 E5 9E E1 5E 5B 30 D7 FF 1B 56 1E 68 3F 45 }
$cs_8 = { FF 1C B0 66 59 DA 3E C3 C7 66 22 F7 A4 E9 AB 39 }
$cs_9 = { AD 39 5D 2D 9C 5F DD 78 A3 55 CB F5 AB 65 FA 62 }
$cs_10 = { 7D 77 C0 15 EA 00 94 91 2D AB F2 20 7A 95 4A 84 }
$cs_11 = { 0C 5B 5E EE 04 DE 9B 79 16 99 BB 1F EB B5 57 00 }
$cs_12 = { 51 CC AB DB C5 D5 BD 2A 4D F0 A9 D6 EB 05 50 FB }
$cs_13 = { 19 56 74 4F DC 5F 81 E0 59 63 D6 DF F9 24 BD 36 }
$cs_14 = { 1E 74 75 CF 5A 5A F6 6A 79 A4 F3 F1 7F 87 56 17 }
$cs_15 = { DE CB AA 66 4B FB D7 1B 22 A3 17 53 AF EB DD 1A }
condition:
any of ($email, $ip*, $domain*, $md5*, $cs*)
}