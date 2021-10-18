# Izvještaj s laboratorijskih vježbi

## Zadatak

Realizirati man in the middle napad iskorištavanjem ranjivosti ARP protokola. 

Student će testirati napad u virtualiziranoj Docker mreži (Docker container networking) koju čine 3 virtualizirana Docker računala (eng. container):

- dvije žrtve station-1
- station-2
- napadač evil-station.

Za izvođenje ove vježbe koristili smo unaprijed izrađene skripte i konfiguracijske datoteke kako bismo mogli upravljati docker containerima, koji su nam predstavljali računala unutar mreže.

Pokretali smo ih skriptom **./start.sh** , a zaustavljali pomoću **./stop.sh**

Za pokretanje interaktivnog shella za svaki container koristili smo naredbu (u ovom primjeru za station-2):

**$** **docker exec -it station-2 bash**

Nakon toga smo pomoću netcata iz jednog containera otvorili port, i na njega se spojili s drugog containera:

station-1: **$ netcat -lp 9000**

station-2: **$ netcat station-1 9000**

Za realizaciju napada koristili smo alat arpspoof kojeg pozivamo iz containera evil-station, i govorimo mu na kojim stationima želimo izvršiti napad:

**$ arpspoof -t station-1 station-2**

Pokretanjem naredbe **$tcpdump** možemo pratiti tok prometa kroz mrežu.

Ukoliko želimo ne samo pratiti, već i prekinuti komunikaciju između dvaju napadnutih stationa za to koristimo naredbu: **$ echo 0 > /proc/sys/net/ipv4/ip_forward** Ova naredba nam zaustavlja protok prometa od "man-in-the-middle" postaje prema finalnoj destinaciji. Napad koji smo realizirali na vježbama presretao je podatke samo iz jednog smjera, ali napad se može izvršiti i tako da se presretnu podaci neovisno o tome u kojem smjeru se šalju.

