Am implementat toate cerințele temei: IPv4, LPM, ICMP și ARP-ul.

1. IPv4

Am făcut în ordine verificările pentru checksum, apoi pentru TTL,
care dacă în pachet ttl < 1 îi va da drop la pachet.
(check_checksum, ttl_handler).

Apoi iau intrarea din routing table cu ajutorul functiei rtable_handler luându-mi o intrare RTableEntry (route_table_entry*)
După aceasta iau din tabela arp cu next_hop-ul din structura RTableEntry, unde obțin interfața cât și mac-ul unde trebuie să trimit.

Trimit pachetul.

2. LPM
Acesta este implementat pentru obținerea intrării din tabela de rutare.
Am implementat un trie cu alfabetul 0 și 1 (bitii din adresa ip), de lungimea măștii.
Timpul de execuție este de O(cel mult de lungimea unei adrese ipv4), lungimea adresei ipv4 fiind 32 de biți, putem spune că este O(1).

3. ICMP

ICMP-ul intră în ecuație când ttl-ul (TIME_EXCEEDED), când nu se găsește adresa ip în tabela de routare(DEST_UNREACHABLE),
cât și atunci când se trimite un pachet cu adresa destinație a router-ului(ECHO_REPLY)

4. ARP
Acesta fiind împărțit în ARP Request și ARP Reply.

ARP Request se întâmplă atunci când router-ul nu are o intrare în tabela arp și face un request de tip BROADCAST pentru a obține mac-ul destinației. Pachetul fiind introdus într-o coadă și este scos și trimis atunci când primește un ARP REPLY, pentru a fi trimis mai departe la destinație.

ARP REPLY se întâmplă când un ARP REQUEST este primit de el și adresa destinație este al lui.



