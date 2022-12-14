# I. Protokół OSPF

## 1. OSPF

**OSPF** to protokół routingu stanu łącza opracowany jako alternatywa dla RIP.
Wykorzystuje on koncepcje obszarów.

**Komunikaty OSPF są wykorzystywane do tworzenia i utrzymywanie trzech następujących baz danych OSPF:**

- **Baza przyległości (Adjacency database)** - Tworzy tablicę sąsiadów. - *show ip ospf neighbor*
- **Baza stanu łącza (Link-state database - LSDB)** - To tworzy tablicę topologii. *show ip ospf database*
- **Baza przekazywania (Forwarding database)** - To tworzy tablicę routingu. *show ip route*

Router używający OSPF buduje tablicę topologii przy użyciu obliczeń opartych na **algorytmie Dijkstry pierwszej najkrótszej ścieżki (shortest-path first - SPF)**.

W tym celu algorytm SPF tworzy tzw. **drzewo SPF**, każdy router umieszczany jest w korzeniu drzewa, po czym obliczana jest najkrótsza ścieżka do każdego węzła. Następnie na podstawie utworzonego drzewa SPF obliczana jest najlepsza ścieżka. Ostatecznie OSPF wstawia najlepsze ścieżki do tablicy przekazywania, na podstawie której tworzona jest tablica routingu.

## 2. Proces routingu stanu łącza

1. **Ustanowienie przyległości sąsiadów** - wysyłanie pakietów Hello, aby ustalić czy na danym łączu znajdują się sąsiedzi.
2. **Wymiana komunikatów o stanie łącza (LSA)** - pakiety LSA zawierające informacje na temat stanu oraz kosztu każdego bezpośrednio podłączonego łącza wysyłane są zalewowo do wszystkich sąsiadów.
3. **Tworzenie bazy stanów łącza** - Na podstawie pakietów LSA Routery tworzą **tablicę topologii (LSDB)**.
4. **Wykonanie algorytmu SPF** - Routery wykonują algorytm SPF.
5. **Wybór najlepszej trasy** - najlepsze ścieżki oferowane są do tablicy routingu IP.

## 3. OSPF wieloobszarowy zalety:
- Mniejsze tablice routingu
- Zmniejszony narzut aktualizacji stanu łącza
- Zmniejszona częstotliwość obliczeń SPF

![Zmiany stanu łącza dotyczą tylko bieżącego obszaru](img/1.png)

## 4. OSFPv3
To odpowiednik OSPFv2 służacy do **wymiany prefiksów IPv6**.

## 5. Rodzaje pakietów OSPF

![Rodzaje pakietów OSPF](img/2.png)

**DR** - Designed Router; **BDR** - Backup Designed Router

## 6. Stany protokołu OSPF:

![Stany protokołu OSPF](img/3.png)

# II. Konfiguracja jednoobszarowego OSPFv2

## 1. Identyfikator routera
To wartość 32-bitowa, która służy do jednoznacznej identyfikacji routera. Identyfikator ten służy do wykonywania następujących czynności:

- **Uczestniczenie w synchronizacji baz danych OSPF** - Podcas stanu Exchange, router z najwyższym identyfikatorrem routera jako pierwszy wyśle pakiety opisu bazy danych (DBD).
- **Uczestniczenie w wyborze routera desygnowanego (DR)** - router z najwyższym id jest DR, drugi najwyższy BDR.

## 2. Maska blankietowa (wildcard mask)
To odwrotność maski podsieci. (255.255.255.0 = 0.0.0.255).

![Proces przypisywania identyfikatora](img/4.png)

## 3. Interfejsy pasywne 
Domyślnie komunikaty OSPF wysyłane są przez wszystkie interfejsy dołączone do protokołu OSPF. Jednak w praktyce powinny one być wysyłane tylko na tych interfejsach, na których jest połączenie z innym routerami z uruchomionym OSPF. 

Wysyłanie niepotrzebnych komunikatów może wpływać na działanie sieci na trzy sposoby:

- **Nieefektywne wykorzystanie pasma**
- **Nieefektywne wykorzystanie zasobów**
- **Zwiększone ryzyko bezpieczeństwa**

## 4. DROTHER
Routery, które nie są ani DR ani BDR.

## 5. Potrzebne komendy:
- **router ospf process-id** - włączenie OSPFv2.
- **router-id** - ustawienie identyfikatora routera.
- **clear ip ospf process** - wyczyszczenie procesu OSPF (w tym reset relacji przylegania).
- **show ip protocols** - daje możliwość zobaczenia identyfikatora routera oraz pasywnych interfejsów.
- **network network-address wildcard-mask area area-id** - włączenie protokołu OSPF na interfejsach.
- **ip ospf process-id area area-id** - pozwala na konfiguracje OSPf bezpośrednio na interfejsie zamiast polecenia **network**.
- **passive-interface** - ogranicza wysyłanie komunikatów dotyczących routingu przez interfejs. Komenda *passive-interface default* sprawia, że wszystkie interfejsy stają się pasywne.
- **show ip ospf interface** - wyświetla DR i BDR na interfejsie, rolę routera, bieżący koszt.
- **ip ospf network point-to-point** - zmienia typ wyznaczonej sieci na punkt-punkt i wyłącza proces wyboru DR/BDR.
- **ip ospf priority value** - ustawia priorytet interfejsu (od 0 do 255).
- **auto-cost reference-bandwidth *Mbps*** - zmienia referencyjną szerokośc pasma (co pozwala na zmianę kosztu dla interfejsów szybszych niż Fast Ethernet).
- **ip ospf cost *value*** - zmienia wartość kosztu ogłaszaną przez lokalny router OSPF do innych routerów OSPF .
- **ip ospf hello-interval *seconds*** - zmienia interwał hello.
- **ip ospf dead-interval *seconds*** - zmienia interwał dead.
- **ip route 0.0.0.0 0.0.0.0 *[next-hop-address | exit-interface]*** - domyślna trasa statyczna
- **default-information originate** - nakazuje routerowi być źródłem informacji o trasie domyślnej i propagowanie statycznej trasy domyślnej w aktualizacjach OSPF.
- **show ip interface brief** - sprawdza, czy żądane interfejsy są aktywne z poprawnym adresowaniem IP.
- **show ip route** - sprawdza, czy tablica routingu zawiera wszystkie oczekiwane trasy.

## 6. Koszt jako metryka w OSPF
Protokoły routingu używają **metryki** w celu wyznaczenia najlepszej trasy dla pakietu przez sieć. **Metryka** jest miarą nakładu wymaganego do przesłania pakietu przez dany interfejs.

Protokół OSPF używa jako metryki **kosztu ścieżki**. Im niższy koszt, tym lepsza trasa do celu.

**Koszt = referencyjna szerokość pasma / szerokość pasma interfejsu**

Wartość kosztu OSPF musi być **liczbą całkowitą**.

![Domyślne koszty OSPF na urządzeniach Cisco](img/5.png)

![Koszt OSPF przy referencyjnej szerokości pasma dostosowanej do obsługi łączy 10 Gigabit Ethernet](img/6.png)

## 7. Interwały pakietów Hello
Pakiety OSPFv2 Hello są wysyłane co 10 sekund.

**Interwał Dead** to okres, przez jaki router będzie czekał na odbiór pakietu Hello, zanim zadeklaruje, że sąsiad jest wyłączony. (W Cisco domyślnie jest to 4-krotność interwału Hello, czyli 10 sek).

## 8. Propagowanie domyślnej trasy statycznej w OPSFv2

**Router brzegowy (router bramy)** - to router podłączony do Internetu, który powinien propagować domyślną trasę do innych routerów w lokalnej sieci.

**Router brzegowy systemu autonomicznego (Autonomous System Boundary Router, ASBR)** - router, który znajduję się pomiędzy domeną routingu OSPF a siecią bez OSPF.

# III. Koncepcje bezpieczeństwa sieci

![Pojęcia bezpieczeństwa](img/7.png)

## 1. Wektory ataków sieciowych

**Wekor ataku** - to ścieżka, dzięi której podmiot zagrożenia może uzyskać dostęp do serwera, hosta lub sieci. Wektory mogą pochodzić ze zewnątrz lub wewnąrz.

## 2. Typy hakerów

![Typy hakerów](img/8.png)

## 3. Terminy dotyczące hackingu

![Terminu dotyczące hackingu](img/9.png)

## 4. Narzędzia do testowania penetracji

![Narzędzia do testowania penetracji](img/10.png)


## 5. Typy ataków

![Typy ataków](img/11.png)

# VII. Koncepcje sieci WAN

## 1. Topologie WAN

- **Punkt-punkt**
- **Hub-and-spoke** - umożliwia współużytkowanie pojedynczego interfejsu na routerze centralnym (hub) przez wszystkie routery obwodowe (spoke).

![Hub-and-spoke](img/12.png)

- **Dual-homed** - zapewnia redundancję. Router centralny jest podwojony w lokalizacji a te nadmiarowo podłączone do routerów obwodowych w chmurze WAN.

![Dual-homed](img/13.png)

- **Pełnej siatki** - wykorzystuje wiele obwodów wirtualnych do łączenia wszystkich lokalizacji.

![Topologia pełnej siatki](img/14.png)

- **Częściowej siatki** - łączy wiele, ale nie wszystkie lokalizacje.

![Topologia częściowej siatki](img/15.png)

## 2. Łącza operatorów
**SLA** - umowa o poziomie usług podpisywana między organizacją a usługodawcą. Przedstawia ona oczekiwane usługi związane z niezawodnością i dostępnością połączenia.

## 3. Standardy sieci WAN

Nowoczesne standardy sieci WAN są definiowane i zarządzane przez wiele uznanych organów, w tym:

- **TIA/EIA** - Telecommunications Industry Association and Electronic Industries Alliance
- **ISO** - International Organization for Standardization
- **IEEE** - Institute of Electrical and Electronics Engineers

## 4. Sieci WAN w modelu OSI

![Sieci WAN w modelu OSI](img/16.png)

## 5. Terminologia WAN

![Terminologia WAN](img/17.png)


## 6. Urządzenia sieci WAN

![Urządzenia sieci WAN](img/18.png)

## 7. Komunikacja szeregowa
W sieciach WAN stosowana jest komunikacja szeregowa.

## 8. Komunikacja z komutacją łączy
**Sieć z komutacją łączy** ustanawia dedykowany obwód (lub kanał) między punktami końćowymi, zanim użytkownicy będą mogli się komunikować.

Podczas transmisji w sieci z komutacją łączy cała komunikacja korzysta z tej samej ścieżki. Cała stała pojemność przydzielona do obwodu jest dostępna na czas połączenia, niezależnie od tego, czy są informacje do transmisji, czy nie. Może to prowadzić do nieefektywności w użyciu obwodu. Z tego powodu komutacja łączy zasadniczo nie nadaje się do przesyłania danych.

Dwa najpopularniejsze typy technologii WAN z komutacją łączy to **publiczna komutowana sieć telefoniczna (PSTN)** i **sieć cyfrowa z integracją usług (ISDN)**.

## 9. Komunikacja z przełączaniem pakietów

W przeciwieństwie do komutacji łączy, przełączanie pakietów dzieli dane ruchu na pakiety, które są kierowane w sieci współużytkowanej. Przełączanie pakietów, nie wymaga zestawienia specjalnego obwodu/połączenia, ponadto pozwalają kilku urządzeniom komunikować się za pomocą tego samego kanału.

Typowe rodzaje technologii WAN z przełączaniem pakietów to **Ethernet WAN (Metro Ethernet)**, **Multiprotocol Label Switching (MPLS)**, a także starszy **Frame Relay** i starszy **Asynchronous Transfer Mode (ATM)**.

## 10. SDH, SONET i DWDM
Istnieją dwa optyczne standardy warstwy 1 OSI dostępne dla dostawców usług:

- **Synchronous Digital Hierarchy (SDH)** to globalny standard transportu danych za pomocą kabla światłowodowego.
- **Synchronous Optical Networking (SONET)** to norma północnoamerykańska, która świadczy te same usługi co SDH.

**Dense Wavelength Division Multiplexing (DWDM)** to nowsza technologia, która zwiększa nośność danych SDH i SONET poprzez jednoczesne wysyłanie wielu strumieni danych (multipleksowanie) przy użyciu różnych długości fal światła, jak pokazano na rysunku.

## 11. MPLS

**Multiprotocol Label Switching (MPLS)** to wysokowydajna technologia routingu WAN dla dostawcy usług umożliwiająca łączenie klientów bez względu na metodę dostępu lub typ obciążenia. MPLS obsługuje różne metody dostępu klienta (np. Ethernet, DSL, Cable, Frame Relay). MPLS może enkapsulować ruch wszystkich typy protokołów, w tym IPv4 i IPv6.

# IX. Koncepcje QoS

## 1. Stałe opóźnienie

To określony czas, jaki trwa określony proces, na przykład czas potrzebnny na umieszczenie go na nośniku transmisji.

## 2. Zmienne opóźnienie

Zajmuje nieokreślony czas i ma wpływ na takie czynniki, jak ilość ruchu która jest przetwarzana.

## 3. Źródła opoźnienia

![Źródła opóźnienia](img/19.png)

## 4. Jitter

Zmienność wartości opóźnienia odebranych pakietów. Z powodu przeciążenia sieci, niewłaściwego kolejkowania lub błędów konfiguracji, opóźnienie między poszczególnymi pakietami może się zmieniać, a nie pozostawać stałe.

## 5. Utracone pakiety

Bez żadnych mechanizmów QoS pakiety są przetwarzane w kolejności, w jakiej zostały odebrane. W przypadku przeciążenia urządzenia sieciowe mogę odrzucać pakiety. Oznacza to, że pakiety wideo czy głosowe będą odrzucane z taką samą częstotliwością jak inne (np. e-mail, http).

## 6. Bufor opóźnienia

Mechanizm kompensujący napotkany przez router jitter. Musi on burforować pakiety, a następnie odtwarzać je w stały strumieniu. Pakiety cyfrowe są późnień konwertowane na analogowy strumień audio.

![Bufor opóźnienia odtwarzania kompensuje jitter](img/20.png)

W przypadku małym strat (jak pakiet) **cyfrowy procesor sygnałowy (DSP)** interpoluje dźwięk i sprawia że problem nie jest słyszalny. 

## 7. Charakterystyka ruchu głosowego

![Charakterystyka ruchu głosowego](img/21.png)

## 8. Charakterystyka ruchu wideo

![Charakterystyka ruchu wideo](img/22.png)

## 9. Charakterystyka ruchu danych

![Charakterystyka ruchu danych](img/23.png)

## 10. Czynniki, które należy wziąć pod uwagę w przypadku opóźnienia danych

![Czynniki, które należy wziąć pod uwagę w przypadku opóźnienia danych](img/24.png)

## 11. Algorytmy QoS

**Algorytmy QoS przedstawione w kursie:**

- Pierwszy wejście, pierwsze wyjście (First-in, first-out - FIFO)
- Ważone uczciwe kolejkowanie (Weighted Fair Queuing - WFQ)
- Uczciwe kolejkowanie oCzęśće na klasach (Class-Based Weighted Fair Queuing - CBWFQ)
- Kolejkowanie o niskim opóźnieniu (Low Latency Queuing - LLQ)

## 12. First In First Out

Znana również jako **„kto pierwszy, ten lepszy”**, bufory i pakiety przesyłek dalej w kolejności ich przybycia.

## 13. Ważone uczciwe kolejkowanie (Weighted Fair Queuing - WFQ)

Jest zautomatyzowaną metodą planowania, która zapewnia uczciwą alokację przepustowości dla całego ruchu sieciowego. WFQ nie zezwala na konfigurację opcji klasyfikacji. WFQ stosuje priorytet lub wagi do zidentyfikowanego ruchu i klasyfikuje go do rozmów lub przepływów.

WFQ następnie określa, ile przepustowości każdy przepływ jest dozwolony w stosunku do innych przepływów. Algorytm przepływowy używany przez WFQ jednocześnie **planuje interaktywny ruch z przodu kolejki** w celu skrócenia czasu reakcji. Następnie dość dzieli pozostałą przepustowość wśród przepływów o wysokiej przepustowości. Funkcja WFQ umożliwia nadanie niewielkiemu, interaktywnemu ruchowi, na przykład sesjom Telnet i głosu, pierwszeństwa w stosunku do dużego ruchu, takiego jak sesje FTP.

WFQ klasyfikuje ruch na różne przepływy w oparciu o adresowanie nagłówków pakietów.

**Ograniczenia WFQ:**

- Funkcja WFQ nie jest obsługiwana w przypadku tunelowania i szyfrowania, ponieważ te funkcje modyfikują informacje o zawartości pakietów wymagane przez funkcję WFQ do klasyfikacji.
- Nie oferuje stopnia precyzyjnej kontroli nad alokacją pasma, jaki oferuje CBWFQ.


## 14. Uczciwe kolejkowanie oparte na klasach (Class-Based Weighted Fair Queuing - CBWFQ)

**Class-Based Weighted Fair Queuing (CBWFQ)** rozszerza standardową funkcjonalność WFQ, aby zapewnić obsługę klas ruchu zdefiniowanych przez użytkownika. Za pomocą CBWFQ definiujesz klasy ruchu na podstawie kryteriów dopasowania, w tym protokołów, list kontroli dostępu (ACL) i interfejsów wejściowych.

## 15. Kolejkowanie o niskim opóźnieniu (Low Latency Queuing - LLQ)
**Funkcja kolejki o niskim opóźnieniu (LLQ)** zapewnia ścisłe kolejkowanie priorytetowe (PQ) do CBWFQ. Ścisłe PQ umożliwia wysyłanie pakietów wrażliwych na opóźnienia, takich jak głos przed pakietami w innych kolejkach. LLQ zapewnia ścisłą kolejkę priorytetową dla CBWFQ, zmniejszając drgania w rozmowach głosowych.

![Przykład LLQ](img/25.png)

# 16. Modele do wdrażania QoS

![Modele do wdrażania QoS](img/26.png)

# 17. Best Effort

Podstawowym założeniem Internetu jest dostarczanie pakietów z największą starannością i nie daje żadnych gwarancji. Podejście to jest nadal dominujące w Internecie i pozostaje właściwe dla większości celów.

Model best-effort jest podobny w koncepcji do wysyłania listu za pomocą zwykłej poczty. Twój list jest traktowany dokładnie tak samo jak każdy inny list. W modelu „najlepszych wysiłków” list może nigdy nie nadejść, a jeśli nie masz osobnych ustaleń dotyczących powiadamiania z odbiorcą listu, możesz nigdy nie wiedzieć, że list nie dotarł.

**Korzyści i wady modelu best-effort**

![Korzyści i wady modelu best-effort](img/27.png)

# 18. IntServ

IntServ zapewnia kompleksową QoS, której wymagają aplikacje czasu rzeczywistego. IntServ jawnie zarządza zasobami sieciowymi, aby zapewnić QoS dla poszczególnych przepływów lub strumieni, czasami nazywanych mikroprzepływami. Wykorzystuje mechanizmy rezerwacji zasobów i kontroli dostępu jako elementy składowe do ustanowienia i utrzymania jakości usług. Jest to podobne do koncepcji znanej jako „twarde QoS”. Twarde QoS gwarantuje charakterystykę ruchu, taką jak przepustowość, opóźnienia i współczynniki utraty pakietów, od początku do końca. Twarde QoS zapewnia zarówno przewidywalne, jak i gwarantowane poziomy usług dla aplikacji o znaczeniu krytycznym.

W modelu IntServ aplikacja przed wysłaniem danych żąda określonego rodzaju usługi z sieci. Aplikacja informuje sieć o swoim profilu ruchu i żąda określonego rodzaju usługi, która może obejmować wymagania dotyczące przepustowości i opóźnień. IntServ używa protokołu Resource Reservation Protocol (RSVP) do sygnalizowania zapotrzebowania na QoS ruchu aplikacji wzdłuż urządzeń na ścieżce od końca do końca w sieci. Jeśli urządzenia sieciowe na ścieżce mogą zarezerwować niezbędną przepustowość, pierwotna aplikacja może rozpocząć transmisję. Jeśli żądana rezerwacja nie powiedzie się na ścieżce, aplikacja źródłowa nie wysyła żadnych danych.

# 19. DiffServ
**Model usług zróżnicowanych (DiffServ)** QoS określa prosty i skalowalny mechanizm klasyfikowania i zarządzania ruchem sieciowym.

DiffServ może zapewnić „prawie gwarantowaną” jakość usług, a jednocześnie jest opłacalne i skalowalne.

Model DiffServ jest podobny w koncepcji do wysyłania paczki za pomocą usługi dostawy. Wysyłając paczkę żądasz (i płacisz) za odpowiedni poziom usług. W całej sieci pakietów poziom usług, za który zapłaciłeś, jest rozpoznawany, a pakiet otrzymuje preferencyjną lub normalną usługę, w zależności od tego, o co prosiłeś.

Gdy host przekazuje ruch do routera, router klasyfikuje przepływy w agregatach (klasach) i zapewnia odpowiednią politykę QoS dla klas. DiffServ wymusza i stosuje mechanizmy jakości usług na zasadzie przeskok po przeskoku, jednolicie nadając globalne znaczenie każdej klasie ruchu, aby zapewnić zarówno elastyczność, jak i skalowalność. Na przykład DiffServ można skonfigurować tak, aby grupował wszystkie przepływy TCP jako jedną klasę i przydzielał przepustowość dla tej klasy, a nie dla poszczególnych przepływów, jak zrobiłby to IntServ. Oprócz klasyfikowania ruchu DiffServ minimalizuje wymagania dotyczące sygnalizacji i utrzymania stanu na każdym węźle sieci.

![Wady i zalety DiffServ](img/30.png)

# 20. Narzędzia do wdrażania QoS

![Narzędzia do wdrażania QoS](img/31.png)

# 21. Sekwencja QoS

![Sekwencja QoS](img/32.png)