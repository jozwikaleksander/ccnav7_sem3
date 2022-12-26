# 📝 CCNA

My notes from CCNAv7 sem3.

## 📜 Table of contents

<ul>
<li><a href="#i.-protokół-ospf">I. Protokół OSPF</a>
<ul>
<li><a href="#ospf">1. OSPF</a></li>
<li><a href="#proces-routingu-stanu-łącza">2. Proces routingu stanu łącza</a></li>
<li><a href="#zalety-wieloobszarowego-ospf">3. Zalety wieloobszarowego OSPF</a></li>
<li><a href="#osfpv3">4. OSFPv3</a></li>
<li><a href="#rodzaje-pakietów-ospf">5. Rodzaje pakietów OSPF</a></li>
<li><a href="#stany-protokołu-ospf">6. Stany protokołu OSPF</a></li>
</ul></li>
<li><a href="#ii.-konfiguracja-jednoobszarowego-ospfv2">II. Konfiguracja jednoobszarowego OSPFv2</a>
<ul>
<li><a href="#identyfikator-routera">1. Identyfikator routera</a></li>
<li><a href="#maska-blankietowa-wildcard-mask">2. Maska blankietowa (wildcard mask)</a></li>
<li><a href="#interfejsy-pasywne">3. Interfejsy pasywne</a></li>
<li><a href="#drother">4. DROTHER</a></li>
<li><a href="#potrzebne-komendy">5. Potrzebne komendy</a></li>
<li><a href="#koszt-jako-metryka-w-ospf">6. Koszt jako metryka w OSPF</a></li>
<li><a href="#interwały-pakietów-hello">7. Interwały pakietów Hello</a></li>
<li><a href="#propagowanie-domyślnej-trasy-statycznej-w-opsfv2">8. Propagowanie domyślnej trasy statycznej w OPSFv2</a></li>
<li><a href="#źródła-uzupełniające">9. Źródła uzupełniające</a></li>
</ul></li>
<li><a href="#iii.-koncepcje-bezpieczeństwa-sieci">III. Koncepcje bezpieczeństwa sieci</a>
<ul>
<li><a href="#wektory-ataków-sieciowych">1. Wektory ataków sieciowych</a></li>
<li><a href="#typy-hakerów">2. Typy hakerów</a></li>
<li><a href="#terminy-dotyczące-hackingu">3. Terminy dotyczące hackingu</a></li>
<li><a href="#narzędzia-do-testowania-penetracji">4. Narzędzia do testowania penetracji</a></li>
<li><a href="#typy-ataków">5. Typy ataków</a></li>
<li><a href="#rodzaje-złośliwego-oprogramowania">6. Rodzaje złośliwego oprogramowania</a>
<ul>
<li><a href="#wirus">6.1. Wirus</a></li>
<li><a href="#koń-trojański">6.2. Koń trojański</a></li>
</ul></li>
<li><a href="#rekonesans">7. Rekonesans</a></li>
<li><a href="#ataki-dostępu">8. Ataki dostępu</a>
<ul>
<li><a href="#ataki-na-hasło">8.1. Ataki na hasło</a></li>
<li><a href="#ataki-fałszowania">8.2. Ataki fałszowania</a></li>
<li><a href="#wykorzystanie-zaufania">8.3. Wykorzystanie zaufania</a></li>
<li><a href="#przekierowanie-portów">8.4. Przekierowanie portów</a></li>
<li><a href="#atak-man-in-the-middle">8.5. Atak Man-in-the-middle</a></li>
<li><a href="#przepełnienie-bufora">8.6. Przepełnienie bufora</a></li>
</ul></li>
<li><a href="#ataki-socjotechniczne">9. Ataki socjotechniczne</a></li>
<li><a href="#ataki-dos-i-ddos">10. Ataki DoS i DDoS</a>
<ul>
<li><a href="#główne-typy-ataków-dos">10.1. Główne typy ataków DoS</a></li>
</ul></li>
<li><a href="#ataki-ip">11. Ataki IP</a></li>
<li><a href="#ataki-na-icmp">12. Ataki na ICMP</a></li>
<li><a href="#ataki-wzmacniania-i-obijania">13. Ataki wzmacniania i obijania</a></li>
<li><a href="#ataki-fałszowania-1">14. Ataki fałszowania</a></li>
<li><a href="#usługi-tcp">15. Usługi TCP</a></li>
<li><a href="#ataki-na-tcp">16. Ataki na TCP</a></li>
<li><a href="#ataki-na-udp">17. Ataki na UDP</a></li>
<li><a href="#zatruwanie-arp">18. Zatruwanie ARP</a>
<ul>
<li><a href="#rodzaje-zatrucia-arp">18.1. Rodzaje zatrucia ARP</a></li>
</ul></li>
<li><a href="#ataki-na-dns">19. Ataki na DNS</a></li>
<li><a href="#tunelowanie-dns">20. Tunelowanie DNS</a>
<ul>
<li><a href="#proces-tunelowania-dns">20.1. Proces tunelowania DNS</a></li>
</ul></li>
<li><a href="#ataki-na-dhcp">21. Ataki na DHCP</a></li>
<li><a href="#triada-pid">22. Triada PID</a></li>
<li><a href="#urządzenia-i-usługi-zabezpieczające">23. Urządzenia i usługi zabezpieczające</a></li>
<li><a href="#zapory">24. Zapory</a></li>
<li><a href="#ips">25. IPS</a></li>
<li><a href="#urządzenia-bezpieczeństwa-treści">26. Urządzenia bezpieczeństwa treści</a></li>
<li><a href="#elementy-bezpiecznej-komunikacji">27. Elementy bezpiecznej komunikacji:</a></li>
<li><a href="#integralność-danych">28. Integralność danych</a>
<ul>
<li><a href="#trzy-znane-funkcje-skrótu">28.1. Trzy znane funkcje skrótu</a></li>
</ul></li>
<li><a href="#uwierzytelnianie-pochodzenia">29. Uwierzytelnianie pochodzenia</a></li>
<li><a href="#poufność-danych">30. Poufność danych</a>
<ul>
<li><a href="#szyfrowanie-symetryczne">30.1. Szyfrowanie symetryczne</a></li>
<li><a href="#szyfrowanie-asymetryczne">30.2. Szyfrowanie asymetryczne</a></li>
</ul></li>
<li><a href="#diffie-hellman-dh">31. Diffie-Hellman (DH)</a></li>
</ul></li>
<li><a href="#iv.-koncepcje-acl">IV. Koncepcje ACL</a>
<ul>
<li><a href="#lista-acl">1. Lista ACL</a>
<ul>
<li><a href="#filtrowanie-ramek">1.1 Filtrowanie ramek</a></li>
<li><a href="#zadanie-acl">1.2. Zadanie ACL</a></li>
<li><a href="#filtrowanie-pakietów-w-modelu-isoosi">1.3. Filtrowanie pakietów w modelu ISO/OSI</a></li>
<li><a href="#wejściowa-i-wyjściowa-lista-acl">1.4. Wejściowa i wyjściowa lista ACL</a></li>
<li><a href="#sposób-działania-standardowej-listy-acl">1.5. Sposób działania standardowej listy ACL</a></li>
</ul></li>
<li><a href="#maski-blankietowe">2. Maski blankietowe</a>
<ul>
<li><a href="#reguły-dopasowania-masek-blankietowych">2.1. Reguły dopasowania masek blankietowych</a></li>
<li><a href="#typy-masek-blankietowych">2.2. Typy masek blankietowych</a></li>
<li><a href="#obliczanie-maski-blankietowej">2.3. Obliczanie maski blankietowej</a></li>
<li><a href="#słowa-kluczowe-w-maskach-blankietowych">2.4. Słowa kluczowe w maskach blankietowych</a></li>
</ul></li>
<li><a href="#wytyczne-tworzenia-acl">3. Wytyczne tworzenia ACL</a>
<ul>
<li><a href="#ograniczona-liczba-acl-na-interfejs">3.1. Ograniczona liczba ACL na interfejs</a></li>
<li><a href="#najlepsze-praktyki">3.2. Najlepsze praktyki</a></li>
<li><a href="#kolejność-instrukcji-acl">3.3. Kolejność instrukcji ACL</a></li>
</ul></li>
<li><a href="#numerowane-i-nazwane-acl">4. Numerowane i nazwane ACL</a>
<ul>
<li><a href="#numerowane-acl">4.1. Numerowane ACL</a></li>
<li><a href="#nazwane-acl">4.2. Nazwane ACL</a></li>
</ul></li>
<li><a href="#umieszczanie-listy-acl">5. Umieszczanie listy ACL</a>
<ul>
<li><a href="#czynniki-wpływające-na-umieszczenie-acl">5.1. Czynniki wpływające na umieszczenie ACL</a></li>
</ul></li>
<li><a href="#źródła-uzupełniające-1">6. Źródła uzupełniające</a></li>
</ul></li>
<li><a href="#v.-konfiguracja-acl">V. Konfiguracja ACL</a>
<ul>
<li><a href="#konfiguracja-standardowych-list-acl-ipv4">1. Konfiguracja standardowych list ACL IPv4</a>
<ul>
<li><a href="#standardowa-numerowana-acl">1.1. Standardowa numerowana ACL</a></li>
<li><a href="#standardowa-nazywana-acl">1.2. Standardowa nazywana ACL</a></li>
<li><a href="#stosowanie-standardowych-list-acl-ipv4">1.3. Stosowanie standardowych list ACL IPv4</a></li>
</ul></li>
<li><a href="#modyfikowanie-list-acl-ipv4">2. Modyfikowanie list ACL IPv4</a>
<ul>
<li><a href="#dwie-metody-modyfikacji-acl">2.1. Dwie metody modyfikacji ACL</a></li>
<li><a href="#statystyki-acl">2.2. Statystyki ACL</a></li>
</ul></li>
<li><a href="#zabezpieczanie-portów-vty-przy-pomocy-standardowej-acl-ipv4">3. Zabezpieczanie portów VTY przy pomocy standardowej ACL IPv4</a>
<ul>
<li><a href="#polecenie-access-class">3.1. Polecenie access-class</a></li>
<li><a href="#przykład-zabezpieczania-dostępu-vty">3.2. Przykład zabezpieczania dostępu VTY</a></li>
</ul></li>
<li><a href="#konfiguracja-rozszerzonych-list-acl-ipv4">4. Konfiguracja rozszerzonych list ACL IPv4</a>
<ul>
<li><a href="#rozszerzona-numerowana-lista-acl-ipv4">4.1. Rozszerzona numerowana lista ACL IPv4</a></li>
<li><a href="#rozszerzona-acl-z-opcją-established-tcp">4.2. Rozszerzona ACL z opcją Established TCP</a></li>
<li><a href="#rozszerzona-nazywana-lista-acl-ipv4">4.3. Rozszerzona nazywana lista ACL IPv4</a></li>
</ul></li>
</ul></li>
<li><a href="#vi.-nat-dla-ipv4">VI. NAT dla IPv4</a>
<ul>
<li><a href="#charakterystyka-nat">1. Charakterystyka NAT</a>
<ul>
<li><a href="#prywatne-adresy-internetowe-definiowane-w-dokumencie-rfc-1918">1.1. Prywatne adresy internetowe definiowane w dokumencie RFC 1918</a></li>
<li><a href="#czym-jest-nat">1.2. Czym jest NAT?</a></li>
<li><a href="#terminologia-nat">1.3. Terminologia NAT</a></li>
</ul></li>
<li><a href="#typy-nat">2. Typy NAT</a>
<ul>
<li><a href="#statyczny-nat">2.1. Statyczny NAT</a></li>
<li><a href="#dynamiczny-nat">2.2. Dynamiczny NAT</a></li>
<li><a href="#translacja-pat">2.3. Translacja PAT</a></li>
</ul></li>
<li><a href="#zalety-i-wady-nat">3. Zalety i wady NAT</a>
<ul>
<li><a href="#zalety-nat">3.1. Zalety NAT</a></li>
<li><a href="#wady-nat">3.2. Wady NAT</a></li>
</ul></li>
<li><a href="#konfiguracja-nat">4. Konfiguracja NAT</a>
<ul>
<li><a href="#konfiguracja-statycznego-nat">4.1. Konfiguracja statycznego NAT</a></li>
<li><a href="#konfiguracja-dynamicznego-nat">4.2. Konfiguracja dynamicznego NAT</a></li>
<li><a href="#konfiguracja-pat">4.3. Konfiguracja PAT</a></li>
</ul></li>
<li><a href="#nat-dla-ipv6">5. NAT dla IPv6</a></li>
<li><a href="#źródła-uzupełniające-2">6. Źródła uzupełniające</a></li>
</ul></li>
<li><a href="#vii.-koncepcje-sieci-wan">VII. Koncepcje sieci WAN</a>
<ul>
<li><a href="#cele-sieci-wan">1. Cele sieci WAN</a>
<ul>
<li><a href="#różnice-między-lan-i-wan">1.1 Różnice między LAN i WAN</a></li>
<li><a href="#prywatne-i-publiczne-sieci-wan">1.2. Prywatne i publiczne sieci WAN</a></li>
<li><a href="#topologie-wan">1.3. Topologie WAN</a></li>
<li><a href="#łącza-operatorów">1.4. Łącza operatorów</a></li>
<li><a href="#ewolucja-sieci">1.5 Ewolucja sieci</a></li>
</ul></li>
<li><a href="#operacje-wan">2. Operacje WAN</a>
<ul>
<li><a href="#standardy-sieci-wan">2.1. Standardy sieci WAN</a></li>
<li><a href="#sieci-wan-w-modelu-osi">2.2. Sieci WAN w modelu OSI</a></li>
<li><a href="#terminologia-wan">2.3. Terminologia WAN</a></li>
<li><a href="#urządzenia-sieci-wan">2.4. Urządzenia sieci WAN</a></li>
<li><a href="#komunikacja-szeregowa">2.5. Komunikacja szeregowa</a></li>
<li><a href="#komunikacja-z-komutacją-łączy">2.6. Komunikacja z komutacją łączy</a></li>
<li><a href="#komunikacja-z-przełączaniem-pakietów">2.7. Komunikacja z przełączaniem pakietów</a></li>
<li><a href="#sdh-sonet-i-dwdm">2.8. SDH, SONET i DWDM</a></li>
</ul></li>
<li><a href="#tradycyjna-łączność-wan">3. Tradycyjna łączność WAN</a>
<ul>
<li><a href="#tradycyjne-opcje-łączności-wan">3.1. Tradycyjne opcje łączności WAN</a></li>
<li><a href="#terminologia-wan-1">3.2. Terminologia WAN</a></li>
<li><a href="#opcje-z-komutacją-łączy">3.3. Opcje z komutacją łączy</a></li>
<li><a href="#opcje-z-przełączaniem-pakietów">3.4. Opcje z przełączaniem pakietów</a></li>
</ul></li>
<li><a href="#nowoczesne-technologie-wan">4. Nowoczesne technologie WAN</a>
<ul>
<li><a href="#nowoczesne-opcje-łączności-wan">4.1. Nowoczesne opcje łączności WAN</a></li>
<li><a href="#ethernet-wan">4.2. Ethernet WAN</a></li>
<li><a href="#mpls">4.3. MPLS</a></li>
</ul></li>
<li><a href="#łączność-internetowa">5. Łączność internetowa</a>
<ul>
<li><a href="#technologia-dsl">5.1. Technologia DSL</a></li>
<li><a href="#połączenia-dsl">5.2. Połączenia DSL</a></li>
<li><a href="#dsl-i-ppp">5.3. DSL i PPP</a></li>
<li><a href="#technologia-kablowa">5.4. Technologia kablowa</a></li>
<li><a href="#łącza-światłowodowe">5.5. Łącza światłowodowe</a></li>
<li><a href="#bezprzewodowy-internet-szerokopasmowy">5.6. Bezprzewodowy internet szerokopasmowy</a></li>
<li><a href="#technologia-vpn">5.7. Technologia VPN</a></li>
<li><a href="#opcje-łączenia-do-dostawcy-usług">5.8. Opcje łączenia do dostawcy usług</a></li>
</ul></li>
<li><a href="#źródła-uzupełniające-3">6. Źródła uzupełniające</a></li>
</ul></li>
<li><a href="#viii.-koncepcje-vpn-i-ipsec">VIII. Koncepcje VPN i IPSec</a>
<ul>
<li><a href="#technologia-vpn-1">1. Technologia VPN</a>
<ul>
<li><a href="#wirtualne-sieci-prywatne">1.1. Wirtualne sieci prywatne</a></li>
<li><a href="#korzyści-z-vpn">1.2. Korzyści z VPN</a></li>
<li><a href="#sieci-vpn-typu-site-to-site-i-zdalnego-dostepu">1.3. Sieci VPN typu site-to-site i zdalnego dostepu</a></li>
<li><a href="#vpn-dla-przedsiębiorstw-i-dostawców-usług">1.4. VPN dla przedsiębiorstw i dostawców usług</a></li>
<li><a href="#sieci-dostawców-usług">1.4.2. Sieci dostawców usług</a></li>
</ul></li>
<li><a href="#rodzaje-sieci-vpn">2. Rodzaje sieci VPN</a>
<ul>
<li><a href="#sieci-vpn-zdalnego-dostępu">2.1. Sieci VPN zdalnego dostępu</a></li>
<li><a href="#ssl-vpn-a-ipsec">2.2. SSL VPN, a IPsec</a></li>
<li><a href="#vpn-site-to-site-ipsec">2.3. VPN site-to-site IPSec</a></li>
<li><a href="#gre-przez-ipsec">2.4. GRE przez IPsec</a></li>
<li><a href="#dynamiczne-wielopunktowe-sieci-vpn">2.5. Dynamiczne wielopunktowe sieci VPN</a></li>
<li><a href="#interfejs-wirtualnego-tunelu-ipsec">2.6. Interfejs wirtualnego tunelu IPsec</a></li>
<li><a href="#dostawca-usług-mpls-vpn">2.7. Dostawca usług MPLS VPN</a></li>
</ul></li>
<li><a href="#ipsec">3. IPSec</a>
<ul>
<li><a href="#technologie-ipsec">3.1. Technologie IPSec</a></li>
<li><a href="#wybory-dotyczące-ipsec">3.2. Wybory dotyczące IPSec</a></li>
<li><a href="#poufność">3.2.2. Poufność</a></li>
<li><a href="#integralność">3.2.3. Integralność</a></li>
<li><a href="#uwierzytelnianie">3.2.4. Uwierzytelnianie</a></li>
<li><a href="#diffie-hellman">3.2.5. Diffie-Hellman</a></li>
</ul></li>
<li><a href="#źródła-uzupełniające-4">4. Źródła uzupełniające</a></li>
</ul></li>
<li><a href="#ix.-koncepcje-qos">IX. Koncepcje QoS</a>
<ul>
<li><a href="#stałe-opóźnienie">1. Stałe opóźnienie</a></li>
<li><a href="#zmienne-opóźnienie">2. Zmienne opóźnienie</a></li>
<li><a href="#źródła-opoźnienia">3. Źródła opoźnienia</a></li>
<li><a href="#jitter">4. Jitter</a></li>
<li><a href="#utracone-pakiety">5. Utracone pakiety</a></li>
<li><a href="#bufor-opóźnienia">6. Bufor opóźnienia</a></li>
<li><a href="#charakterystyka-ruchu-głosowego">7. Charakterystyka ruchu głosowego</a></li>
<li><a href="#charakterystyka-ruchu-wideo">8. Charakterystyka ruchu wideo</a></li>
<li><a href="#charakterystyka-ruchu-danych">9. Charakterystyka ruchu danych</a></li>
<li><a href="#czynniki-które-należy-wziąć-pod-uwagę-w-przypadku-opóźnienia-danych">10. Czynniki, które należy wziąć pod uwagę w przypadku opóźnienia danych</a></li>
<li><a href="#algorytmy-qos">11. Algorytmy QoS</a></li>
<li><a href="#first-in-first-out-fifo">12. First In First Out (FIFO)</a></li>
<li><a href="#ważone-uczciwe-kolejkowanie-weighted-fair-queuing---wfq">13. Ważone uczciwe kolejkowanie (Weighted Fair Queuing - WFQ)</a></li>
<li><a href="#uczciwe-kolejkowanie-oparte-na-klasach-class-based-weighted-fair-queuing---cbwfq">14. Uczciwe kolejkowanie oparte na klasach (Class-Based Weighted Fair Queuing - CBWFQ)</a></li>
<li><a href="#tail-drop-porzucenie-ogona">15. Tail drop (porzucenie ogona)</a></li>
<li><a href="#kolejkowanie-o-niskim-opóźnieniu-low-latency-queuing---llq">15. Kolejkowanie o niskim opóźnieniu (Low Latency Queuing - LLQ)</a></li>
<li><a href="#modele-do-wdrażania-qos">16. Modele do wdrażania QoS</a></li>
<li><a href="#best-effort">17. Best Effort</a></li>
<li><a href="#intserv">18. IntServ</a></li>
<li><a href="#diffserv">19. DiffServ</a></li>
<li><a href="#kategorie-narzędzi-do-wdrażania-qos">20. Kategorie narzędzi do wdrażania QoS</a></li>
<li><a href="#sekwencja-qos">21. Sekwencja QoS</a></li>
</ul></li>
</ul>

## 👤 Credits
Project was made by Aleksander Jóźwik ([@jozwikaleksander](https://github.com/jozwikaleksander)).