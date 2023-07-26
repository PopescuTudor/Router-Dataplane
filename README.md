# Router-Dataplane
Proiect in limbajul C ce implementeaza dataplane-ul unui router.

## 1) Procesul de dirijare

Se face verificarea initiala a pachetului: daca pachetul are adresa mac destinatie diferita de adresa mac a interfetei router-ului
destinata host-ului ce trimite pachetul sau daca pachetul nu este de tip broadcast, atunci ignor pachetul 

Daca adresa IP a interfetei router-ului pe care primesc pachetul este diferita de adresa de destinatie din ip header, 
atunci pachetul nu este pt router, ci trebuie dirijat mai departe, catre host-ul destinatie (forwarding).
Cu functia checksum() din schelet verific checksum-ul din ip header. Daca checksum-ul recalculat nu este acelasi cu cel vechi,
ignor pachetul.
O ultima verificare este cea a Time to live -ului. Daca ttl nu este prea mic (<=1) pot trece mai departe, 
la cautarea in tabela de rutare a next_hop.
Dupa aflarea celei mai bune rute (next_hop), cautam adresa mac, in tabela ARP, ce corespunde adresei IP gasite in rtable.
Pentru a trimite, in final, pachetul catre destinatia corecta, actualizez ethernet header-ul cu noua adresa MAC gasita pt destinatie,
iar pentru sursa, gasim cu "get_interface_mac()" adresa MAC pentru interfata router-ului pe care voi dirija pachetul.

## 2)LPM

Se sorteaza rtable dupa functia compare(), prioritate avand prefixul, iar apoi masca.
Cu functia get_best_route(), caut (liniar) intrarea in rtable cu cel mai lung subnet mask.

## 3)ARP

Utilizez protocolul ARP atunci cand trebuie sa trimit un pachet catre o adresa IP, dar nu stiu adresa MAC a destinatiei.

Salvez intr-o coada de pachete de tip arp_queue_entry pachetele care nu pot fi trimise, pentru ca nu stiu adresa MAC a destinatiei. 
Astfel, ele raman practic in asteptare, pana cand primesc raspunsul ARP request-ului, cand le pot trimite utilizand functia send_waiting_packets().
In aceasta functie, parcurg coada de pachete, iar daca vreunul are adresa IP a destinatiei egala cu adresa IP a sender-ului din ARP reply, il trimit.
Altfel, il pun inapoi in coada.

Pentru a afla adresa MAC a destinatiei, generez un  ARP request, cu adresa IP a destinatiei, catre broadcast.
Functia generate_arp_request() pune in adresa destinatie 0xff..ff, iar in adresa sursa adresa MAC a interfetei router-ului pe care
se trimite pachetul.
Dupa ce primesc raspunsul, adaug intrarea in tabela ARP, cu adresa IP si adresa MAC a destinatiei.

In cazul in care primesc un ARP request, folosesc functia generate_arp_reply() pentru a formula un raspuns.
Setez campurile din header-ul ARP, iar in adresa destinatie pun adresa MAC a sender-ului din ARP request.
In adresa sursa pun adresa MAC a interfetei router-ului pe care se trimite pachetul.

## 4)ICMP

Daca pachetul primit este pentru router (are adresa IP a interfetei router-ului ca adresa de destinatie), verific daca pachetul este de tip ICMP.
Daca da, verific daca este de tip echo request si daca checksum-ul este valid. Daca da, trimit un echo reply, folosind functia generate_icmp(), 
cu (type, code) = (0, 0).

De asemenea, utilizez protocolul ICMP pt mesaje de tip "Destination unreachable" si "Time exceeded", cu (type, code) = (3, 0), respectiv (11, 0).

Functia generate_icmp() genereaza header-ul ICMP in functie de type si code (date in parametrii functiei). Interschimbam adresele IP din ip header,
iar pentru adresa MAC, pun adresa MAC a interfetei router-ului pe care se trimite pachetul. 
Checksum-ul trebuie apoi recalculat. 
