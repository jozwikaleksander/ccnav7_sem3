# 📝 CCNA

My notes from CCNAv7 sem3.

## 📜 Table of contents

**I. Protokół OSPF**
   1. OSPF
   2. Proces routingu stanu łącza
   3. Zalety wieloobszarowego OSPF
   4. OSFPv3
   5. Rodzaje pakietów OSPF
   6. Stany protokołu OSPF
**II. Konfiguracja jednoobszarowego OSPFv2**
   1. Identyfikator routera
   2. Maska blankietowa (wildcard mask)
   3. Interfejsy pasywne
   4. DROTHER
   5. Potrzebne komendy
   6. Koszt jako metryka w OSPF
   7. Interwały pakietów Hello
   8. Propagowanie domyślnej trasy statycznej w OPSFv2
   9. Źródła uzupełniające
**III. Koncepcje bezpieczeństwa sieci**
   1. Wektory ataków sieciowych
   2. Typy hakerów
   3. Terminy dotyczące hackingu
   4. Narzędzia do testowania penetracji
   5. Typy ataków
   6. Rodzaje złośliwego oprogramowania
        6.1. Wirus
        6.2. Koń trojański
   7. Rekonesans
   8. Ataki dostępu
        8.1. Ataki na hasło
        8.2. Ataki fałszowania
        8.3. Wykorzystanie zaufania
        8.4. Przekierowanie portów
        8.5. Atak Man-in-the-middle
        8.6. Przepełnienie bufora
   9. Ataki socjotechniczne
   10. Ataki DoS i DDoS
        10.1. Główne typy ataków DoS
    11. Ataki IP
    12. Ataki na ICMP
    13. Ataki wzmacniania i obijania
    14. Ataki fałszowania
    15. Usługi TCP
    16. Ataki na TCP
    17. Ataki na UDP
    18. Zatruwanie ARP
        18.1. Rodzaje zatrucia ARP
    19. Ataki na DNS
    20. Tunelowanie DNS
        20.1. Proces tunelowania DNS
    21. Ataki na DHCP
    22. Triada PID
    23. Urządzenia i usługi zabezpieczające
    24. Zapory
    25. IPS
    26. Urządzenia bezpieczeństwa treści
    27. Elementy bezpiecznej komunikacji:
    28. Integralność danych
        28.1. Trzy znane funkcje skrótu
    29. Uwierzytelnianie pochodzenia
    30. Poufność danych
        30.1. Szyfrowanie symetryczne
        30.2. Szyfrowanie asymetryczne
    31. Diffie-Hellman (DH)
**IV. Koncepcje ACL**

   1. Lista ACL
        1.1 Filtrowanie ramek
        1.2. Zadanie ACL
        1.3. Filtrowanie pakietów w modelu ISO/OSI
        1.4. Wejściowa i wyjściowa lista ACL
        1.5. Sposób działania standardowej listy ACL
   2. Maski blankietowe
        2.1. Reguły dopasowania masek blankietowych
        2.2. Typy masek blankietowych
        2.3. Obliczanie maski blankietowej
        2.4. Słowa kluczowe w maskach blankietowych
   3. Wytyczne tworzenia ACL
        3.1. Ograniczona liczba ACL na interfejs
        3.2. Najlepsze praktyki
        3.3. Kolejność instrukcji ACL
   4. Numerowane i nazwane ACL
        4.1. Numerowane ACL
        4.2. Nazwane ACL
   5. Umieszczanie listy ACL
        5.1. Czynniki wpływające na umieszczenie ACL
   6. Źródła uzupełniające
**V. Konfiguracja ACL**
   1. Konfiguracja standardowych list ACL IPv4
        1.1. Standardowa numerowana ACL
        1.2. Standardowa nazywana ACL
        1.3. Stosowanie standardowych list ACL IPv4
   2. Modyfikowanie list ACL IPv4
        2.1. Dwie metody modyfikacji ACL
        2.2. Statystyki ACL
   3. Zabezpieczanie portów VTY przy pomocy standardowej ACL IPv4
        3.1. Polecenie access-class
        3.2. Przykład zabezpieczania dostępu VTY
   4. Konfiguracja rozszerzonych list ACL IPv4
        4.1. Rozszerzona numerowana lista ACL IPv4
        4.2. Rozszerzona ACL z opcją Established TCP
        4.3. Rozszerzona nazywana lista ACL IPv4
        VI. NAT dla IPv4
   5. Charakterystyka NAT
        1.1. Prywatne adresy internetowe definiowane w dokumencie RFC 1918
        1.2. Czym jest NAT?
        1.3. Terminologia NAT
   6. Typy NAT
        2.1. Statyczny NAT
        2.2. Dynamiczny NAT
        2.3. Translacja PAT
   7. Zalety i wady NAT
        3.1. Zalety NAT
        3.2. Wady NAT
   8. Konfiguracja NAT
        4.1. Konfiguracja statycznego NAT
        4.2. Konfiguracja dynamicznego NAT
        4.3. Konfiguracja PAT
   9. NAT dla IPv6
   10. Źródła uzupełniające
**VII. Koncepcje sieci WAN**
   1. Cele sieci WAN
        1.1 Różnice między LAN i WAN
        1.2. Prywatne i publiczne sieci WAN
        1.3. Topologie WAN
        1.4. Łącza operatorów
        1.5 Ewolucja sieci
   2. Operacje WAN
        2.1. Standardy sieci WAN
        2.2. Sieci WAN w modelu OSI
        2.3. Terminologia WAN
        2.4. Urządzenia sieci WAN
        2.5. Komunikacja szeregowa
        2.6. Komunikacja z komutacją łączy
        2.7. Komunikacja z przełączaniem pakietów
        2.8. SDH, SONET i DWDM
   3. Tradycyjna łączność WAN
        3.1. Tradycyjne opcje łączności WAN
        3.2. Terminologia WAN
        3.3. Opcje z komutacją łączy
        3.4. Opcje z przełączaniem pakietów
   4. Nowoczesne technologie WAN
        4.1. Nowoczesne opcje łączności WAN
        4.2. Ethernet WAN
        4.3. MPLS
   5. Łączność internetowa
        5.1. Technologia DSL
        5.2. Połączenia DSL
        5.3. DSL i PPP
        5.4. Technologia kablowa
        5.5. Łącza światłowodowe
        5.6. Bezprzewodowy internet szerokopasmowy
        5.7. Technologia VPN
        5.8. Opcje łączenia do dostawcy usług
   6. Źródła uzupełniające
**VIII. Koncepcje VPN i IPSec**
   1. Technologia VPN
        1.1. Wirtualne sieci prywatne
        1.2. Korzyści z VPN
        1.3. Sieci VPN typu site-to-site i zdalnego dostepu
        1.4. VPN dla przedsiębiorstw i dostawców usług
        1.4.2. Sieci dostawców usług
   2. Rodzaje sieci VPN
        2.1. Sieci VPN zdalnego dostępu
        2.2. SSL VPN, a IPsec
        2.3. VPN site-to-site IPSec
        2.4. GRE przez IPsec
        2.5. Dynamiczne wielopunktowe sieci VPN
        2.6. Interfejs wirtualnego tunelu IPsec
        2.7. Dostawca usług MPLS VPN
   3. IPSec
        3.1. Technologie IPSec
        3.2. Wybory dotyczące IPSec
        3.2.2. Poufność
        3.2.3. Integralność
        3.2.4. Uwierzytelnianie
        3.2.5. Diffie-Hellman
    4. Źródła uzupełniające
**IX. Koncepcje QoS**
   1. Stałe opóźnienie
   2. Zmienne opóźnienie
   3. Źródła opoźnienia
   4. Jitter
   5. Utracone pakiety
   6. Bufor opóźnienia
   7. Charakterystyka ruchu głosowego
   8. Charakterystyka ruchu wideo
   9. Charakterystyka ruchu danych
   10. Czynniki, które należy wziąć pod uwagę w przypadku opóźnienia danych
   11. Algorytmy QoS
   12. First In First Out (FIFO)
   13. Ważone uczciwe kolejkowanie (Weighted Fair Queuing - WFQ)
   14. Uczciwe kolejkowanie oparte na klasach (Class-Based Weighted Fair Queuing - CBWFQ)
   15. Tail drop (porzucenie ogona)
   16. Kolejkowanie o niskim opóźnieniu (Low Latency Queuing - LLQ)
   17. Modele do wdrażania QoS
   18. Best Effort
   19. IntServ
   20. DiffServ
   21. Kategorie narzędzi do wdrażania QoS
   22. Sekwencja QoS

## 👤 Credits
Project was made by Aleksander Jóźwik ([@jozwikaleksander](https://github.com/jozwikaleksander)).