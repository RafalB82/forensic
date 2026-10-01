# CHANGELOG

Wersje narzędzia. Każda tura planu (`PLAN.md`) to jedna wersja; numery
commitów i wyniki weryfikacji są w `PLAN.md` w sekcji „CHECKPOINTY".

## 0.20.0 — ostatni pas testów `appdata`: z 13% do 84%

`core/appdata.py` **68% → 84%**, pokrycie całego pakietu **39,09% → 40,24%**,
242 → **286 testy**. Podłoga podniesiona 65% → 80%.

Ostatnich siedem czytników bez pokrycia, wszystkie z odpowiedzią, którą raport
stawia przed człowiekiem: książka kontaktów, magazyn P2P, log instalacji Play
Store, historia galerii MIUI, `package-usage.list` i skanery tokenów.

Rozróżnienia, których nie było testowanych:

- **kontakt zapisany bez nazwy to nadal zapisany kontakt**, więc `named_contacts`
  to inna liczba niż `contacts`
- **poprawny magazyn P2P bez wierszy ma własne zdanie** i nie może czytać się
  jak baza, której nie dało się otworzyć. Tabele metadanych
  (`android_metadata`, `_shared_version`) są w obu fixture'ach **z wierszami**,
  żeby czytnik, który by je policzył, obalił przypadek pusty
- **log instalacji mówi, którym kontem** coś zainstalowano, a to jest nazwisko w
  raporcie
- **skanery tokenów** trzymają prawdziwy dostęp osobno od ciągu `EAA…` wewnątrz
  base64, bo drugi jest zbiegiem alfabetu, a zgłoszenie go byłoby oskarżeniem

**Dwa ustalenia, nie błędy testów, tylko zachowanie warte opisania:**

1. **`found` jest redundantne, gdy podano pakiet.** Filtr działa **wewnątrz**
   `_appstate_rows`, więc `apps` jest już zawężone do jednego pakietu, zanim
   `found` filtruje je po raz drugi. Obie listy są identyczne. To napisane, nie
   „naprawione": czytnik, który czytałby tabelę dwa razy — raz z filtrem, raz bez —
   mógłby zgodzić się z sam sobą inaczej, gdy plik zmieni się między odczytami,
   a raport z dwiema różnymi liczbami dla jednej bazy zaprasza pytanie, która
   jest prawdziwa.
2. **Szczupły schemat `appstate` to błąd z nazwanym brakującym kolumną.**
   `_appstate_rows` ma fallback dla **jednej** kolumny (`first_download_ms`),
   pozostałych trzynaście pyta bezwarunkowo. Zostawia to niespójność w wyjściu,
   którą warto przypiąć: `rows` wynosi 1 — tabela istnieje i ma jeden wiersz —
   a `apps` jest puste, bo zapytanie padło. **Obie liczby są prawdziwe** i
   czytający, który zobaczy tylko pierwszą, uwierzy, że lista instalacji
   została odczytana.

**Siedem moich błędów**, z kodem dlaczego:

| co napisałem | co jest prawdą |
|---|---|
| `contacts` znika przy braku tabeli | jest `-1` **i** jest `error` — czytnik mówi obie rzeczy |
| `"x" in d is False` | łańcuch porównań, nie to co myślałem |
| filtr zostawia `apps` nietknięte | filtr działa wewnątrz `_appstate_rows` |
| `found` puste, `apps` nie | obie puste — filtr jednostronny |
| szczupły `appstate` się czyta | to `error: no such column` |
| `launches["PhotoActivity"]` | komponent z kropką: `.PhotoActivity` |
| `uid == 10001` | `uid` jest stringiem |

Ten ostatni jest najważniejszy do zapamiętania: **uid przychodzi z dokumentu
JSON, gdzie liczba i liczba-w-tekście są dla czytnika nieodróżnialne**, więc
stringifikacja jest właściwa. Test napisał `int`, bo tak wygląda w Pythonie.

Sprawdzone, że testy łapią regresje: `tincan` liczący tabele metadanych → 2;
dostęp tokenu bez nazwy pola uznany za prawdziwy → 1; `launches` jako liczba
kubelków zamiast sumy → 1.

**Niepokryte i następne:** `whatsapp_identity` (kontener blobów kluczy),
`_people` (rozwiązywanie nazw w Messenger), `preferences_documents`,
`_senders_by_snippet`, `java_serialized`, `integrity`. Dwa z nich są najważniejsze,
bo oba produkują twierdzenia o tym, **kto był w rozmowie**: `whatsapp_identity`
i `_senders_by_snippet`.

## 0.19.0 — testy stanu E2EE, kluczy Wi-Fi i licznika sieciowego

`core/appdata.py` **49% → 68%**, pokrycie całego pakietu **37,69% → 39,09%**,
202 → **242 testy**. Podłoga podniesiona 45% → 65%.

Trzy grupy, wspólne jedno: każda odpowiada na pytanie, które raport stawia przed
człowiekiem.

**Bazy E2EE niosą najostrzejsze sformułowania w całym narzędziu.** Werdykt
„nie ma lokalnie materiału klucza prywatnego", gdy schemat po prostu nie ma
takiej kolumny, to twierdzenie o urządzeniu postawione z braku danych. Dlatego
są **oba schematy** — z kolumną `trusted` i bez niej — bo czytnik ma dla nich
zdanie różne i obie ścieżki były niepokryte. Podobnie trzy werdykty msys
(localna para kluczy > token autoryzacji > brak danych) i ranking między nimi.

**Klucze Wi-Fi leżą jawnie na Androidzie 7, wraz z cudzysłowami**, które
zostawił format pliku. Czytnik, który ich nie zdejmie, raportuje SSID, którego
analyst nigdy nie widział, i PSK, którym nie podłączy sieci. Sieć bez klucza to
nie sieć, która klucz zgubiła — dlatego obok dwóch sieci z kluczem jest trzecia,
otwarta.

**Licznik sieciowy nie ma schematu w tym projekcie.** `ConnectivityService` go
zapisuje, a układ pól to wewnętrzna sprawa frameworka, więc czytnik raportuje
tylko to, co da się odczytać bez zgadywania — a **znacznik milisekund bierze z
nazwy pliku**, nie z wnętrza. Warto to przypiąć, bo czytnik, który znalazłby
pole timestamp i dałby mu pierwszeństwo, wyglądałby staranniej i myliłby się
częściej.

**Fixture ANET musiał dwa razy, i obie porażki są pouczające.** Najpierw nazwy
interfejsów bez cudzysłowów, potem z cudzysłowami ale **z bajtem długości
protobuf**. Za każdym razem czytnik zwrócił pustą listę, co wygląda na
czytnika, który nie działa, a nie na fixture, który nie pasuje do formatu.
Ustalone: ``
`` jest **separatorem**, nie tagiem pola z rozmiarem — w protobufie
między tagiem a ładunkiem stałby varint długości, a wzorzec czytnika tego nie
ma. Layout opisany w fixture i przypięty testem osobno, żeby następny
„uprości" znalazł test, który pada.

**Sześć moich błędów w tej partii**, z kodem dlaczego:

| co napisałem | co jest prawdą |
|---|---|
| fixture `messenger_msys` | przesłania funkcję o tej samej nazwie — `PosixPath is not callable` |
| `pb_string(2, nested)` | `nested` to bajty, nie `str` |
| `identities == 1` | są dwie |
| `msys counts == {}` | są trzy tabele obecne |
| `ssids` w kolejności wstawienia | `sorted()` |
| `3 sieci z kluczem` | cztery sieci, trzy z kluczem |
| ANET: `
` + długość + `"nazwa"` | `
"` + nazwa + `"` |

Ten ostatni kosztował dwa podejścia i jest najważniejszy: **fixture, który nie
pasuje do formatu, wygląda jak zepsuty czytnik.** To ta sama odwrócona
atrybucja co w `_offsets_for` z samotestu, gdzie uszkodzenie lądowało w wolnym
miejscu i było nieodróżnialne od obsłużonego.

Sprawdzone, że testy łapią regresje: `wifi_settings` bez zdejmowania cudzysłowów
→ 2 testy; brak `trusted` dający `0` zamiast informacji o braku kolumny → 1;
protobuf niezaględniający komunikatów zagnieżdżonych → 1.

Podłoga `appdata` podniesiona na 65%. Nadal niepokryte i następne:
`whatsapp_contacts`, `messenger_tincan`, `play_localappstate` z
`_appstate_rows`, `miui_gallery_history`, `package_usage` i skanery tokenów
(`raw_token_hits`, `access_tokens`). Każdy z nich nadal potrzebuje **własnego
schematu**.

## 0.18.0 — testy `appdata`: z 13% do 49% na najważniejszym dla zdrowia module

**`forensic/core/appdata.py` był w 13% i był największą dziurą w tym repo.**
Konta, bazy Chromium, preferencje Messengera, magazyny WhatsAppa, shared-prefs
XML, bloby protobufowe — moduł o największej powierzchni sądowej w projekcie i
najmniejszym pokryciu automatycznym. Ćwiczony ręcznie i przez `verify` na obrazie
referencyjnym, przez pytest w trzynastej części.

Teraz **49%**, a pokrycie całego pakietu **35,13% → 37,69%**. 202 testy (było 143).

**Fixture'y budują prawdziwe pliki** na schematach, których czytnicy naprawdę
pytają — bez obrazu i bez 27 GB do pobrania, kilka milisekund na plik. Schematy
są cytowane z czytników, nie zmyślane: fixture zmyślony z domysłu, jak wygląda
baza WhatsAppa, przeszedłby czytnik, który ma ten domysł zły.

`test_msgstore_fixture_is_the_schema_the_reader_queries` pilnuje, żebymy budowali i
czytnik nie rozjechały się na nazwach kolumn. Fixture, który milczałby o
zdanie, które miał złapać.

Trzy rzeczy, których wcześniej nie było testowanych i które robią złe wnioski o
**człowieku**:

- **nieznany kod typu wiadomości jest liczony, nie pomijany.** Numeracja WhatsAppa
  przesunęła się między kolumnami Androida i tabele **nie zgadzają się**: 16 to
  `live_location` na starszej kolumnie i `call_missed` na nowszej, 20 to
  `sticker` i `live_location`. Zastosowanie niewłaściwego słownika daje etykietę,
  która brzmi wiarygodnie. Test **zmierzony**, nie z komentarza — pierwsza
  wersja twierdziła, że różni się kod 9; nie różni się, w obu jest `document`.
  Zmierzone kody to 16, 20 oraz te, które zna tylko jedna tabela.
- **brakująca tabela to nie zero wierszy.** `_count` zwraca `-1`, co dziwnie
  wygląda, więc znaczenie jest przypięte tam, gdzie powstaje. Test na
  `messages_total` mówi wprost, że brak tabeli `messages` **nie** jest
  raportowany jako zero wiadomości.
- **baza, która się nie otwiera, to nie baza bez niczego.** Trzy przypadki
  rozdzielone: plik nie jest bazą, nagłówek jest, ale schematu nie ma, i baza
  pusta. To ostatnie jest jedyną czystą negatywą i musi nią zostać.

**Wpis o `is_encrypted` jest wadą, nie pochwałą.** Test
`test_is_encrypted_does_not_detect_real_ciphertext` mierzy to wprost: **20/20
prawdziwych szyfrogramów daje `False`**. Warunek to *brak* jakiegokolwiek ciągu
czterech znaków drukowalnych w pierwszych 4 KiB, a losowe bajty dają ~810 takich
ciągów na 64 KiB — czyli warunek, który prawdziwe szyfrowanie spełnia, jest
jednocześnie tym, które odrzuca. **Funkcja nigdzie nie jest wywoływana**, więc
nic zależy od jej odpowiedzi; gdyby ktoś po nią sięgnął, uznałby, że działa.
Naprawa to miara entropii albo usunięcie — **decyzja nie moja**, zapisana.

**Sześć moich błędów w testach, każdy z kodem, dlaczego jest błędem:**

| co napisałem | co jest prawdą |
|---|---|
| kod 9 różni się między tabelami | w obu `document` |
| `shared_prefs_xml` jako wartość | to fixture, nie wartość |
| `silent: 0` w tabeli | `[]` — inny typ w `res.data` |
| `text_strings` wyciąga `"ab"` | wzorzec wymaga czterech znaków |
| `properties_store` znajdzie `"string"` | skanuje tylko po `{` |
| fixture zapisuje wartości jako BLOB | czytnik wymaga `str`; wyszło trzy konta bez nazw |

Ten ostatni jest najciekawszy i dostał własny test: **wiersz z wartością BLOB
produkuje konto bez nazwy, bez dat i bez tokenu**, nazwane na podstawie nazwy
wiersza. Baza z wierszami BLOB zgłasza więcej „kont" niż ma ludzi. Poprawka jest
decyzją o tym, co znaczy wiersz bez czytelnej treści, i **nie została podjęta** —
zapisany jest pomiar.

Sprawdzone, że nowe testy łapią regresje: `_count` zwracające `0` zamiast `-1`
→ 3 testy padają; nieznany kod opisany jako „tekst" → 2 testy padają.

Podłoga pokrycia `appdata` dodana do `tools/check_coverage.py` (45%), żeby nie
mogła się cofnąć. Nadal niepokryte i następne w kolejności: `whatsapp_axolotl`,
`messenger_msys`, `wifi_settings`, `wpa_supplicant`, `network_stats` i helpery
protobuf za `whatsapp_identity` — każdy z nich potrzebuje **własnego schematu**,
a to jest do zrobienia inaczej niż wywołanie funkcji.

Fixture'y są w `tests/appdata_fixtures.py` i ładowane jako `pytest_plugins`
z `conftest.py`. Import ręczny nie działa: pytest daje fixture'owi parametr o tej
samej nazwie, a ruff zgłasza import jako redefinicję (`F811`).

## 0.17.0 — CI: pokrycie i podłogi, które da się zaufać

**Bramka `grep` w samoteście, którą napisałem dzień wcześniej, była zła i
działała złym sposobem.** Krok w `.github/workflows/ci.yml` szukał w
wyrenderowanej tabeli `silent: 0` i `unexpected: []`. W rzeczywistości `silent`
wypisuje się jako `[]`, a nie `0` — i to nie jest literówka, to inny typ w
`res.data`. Wzorzec przestałby pasować przy każdej zmianie szerokości kolumny,
czyli dokładnie wtedy, gdy ktoś go nie zauważy. Teraz asercja czyta **eksport
JSON**: strukturalnie, bez wrażliwości na formatowanie, i obejmuje też wyniki
zestawu uszkodzonych obrazów, których tam wcześniej nie było.

Sprawdzone w obie strony: zaszumiony `corruption.wrong` → `exit=1`, czyste
wyjście → `exit=0`.

**Dwa joby, nie jeden.** `parsers` uruchamia sam test parserów, uciętych i
uszkodzonych obrazów — 53 testy, tylko `e2fsprogs` — bo czerwony krzyż w jobie
ogólnym przy wciąż zielonych parserach jest sygnałem, którego chce się czytać
 dalej. `test` to reszta.

**`tools/check_type_regressions.py` — mypy może spadać, nie może rosnąć.**
Repo jest w 40% otypowane i droga z 62 błędów do zera musi przetrwać każdy commit
po drodze. `mypy forensic` blocking dziś znaczyłoby albo blokowanie wszystkiego,
albo blokowanie na 62 błędach, których nikt nie spłaci w jednym commicie — więc
CI raportuje liczbę, a ten skrypt decyduje, czy się ruszyła. **Per pakiet**, nie
jedna suma: suma zadowala się przypadkiem, bo usunięcie adnotacji w czystym
pliku i dodanie gorszego gdzie indziej zostawia sumę identyczną i zamienia
znane miejsce na nieznane.

Sprawdzone w obie strony: wstrzyknięty błąd w `core/session.py` → `exit=1`,
`core 0 → 1` widoczne osobno; po przywróceniu → `exit=0`.

**Pokrycie: 35,13% z włączonym branch.** Podłoga 35, nie 40 — podłoga ustawiona
na zaokrąglonej w górę liczbie **nie przechodzi na czystym drzewie**, a bramka,
która nie przechodzi zanim ktokolwiek dotknął kodu, to bramka, której się nie
ufa. Branch, nie instrukcje, bo w tym repo wady, które się zdarzyły, to gałęzie
niewykonane lub źle wykonane: krótki odczyt dopełniany zerami zamiast wyjątku,
`if v`, które niczego nie odfiltrowywało bo `-1` jest prawdziwe, i `get(key, 0)`,
którego domyślna wartość robiła raportowanie. Żadna z nich nie zmniejsza licznika
instrukcji.

**Podłogi per czytnik** (`tools/check_coverage.py`), bo jedna suma jest
zadowalająca przypadkiem: ext4 69%, f2fs 81%, erofs 68% — podłogi 60/70/55.
Skrypt sprawdza też, że podłoga w `ci.yml` zgadza się z podłogą w nim samym,
bo rozjeżdżające się stałe w dwóch plikach to dokładnie ten rodzaj bramki, który
przestaje działać po cichu.

W `tools/`, nie w `tests/`. Jako pliki testowe podłogi dawały 0% przy każdym
niepełnym przebiegu — `pytest tests/test_coverage_floor.py` importuje czytniki
bez ich wykonania — a bramka, która nie przechodzi przy własnym uruchomieniu, jest
bramką, którą się pomija.

## Największa dziura, zapisana wprost

`forensic/core/appdata.py` — **13%**. To tam czyta się dowody aplikacji: konta,
bazy Chromium, preferencje Messengera, magazyny WhatsAppa, shared-prefs XML,
bloby protobufowe. **Największa powierzchnia sądowa w projekcie i najmniejsze
pokrycie automatyczne.** W praktyce ćwiczony przez `verify` na obrazie
referencyjnym i ręcznie, przez pytest — w trzynastej części.

To nie jest wezwanie do napisania 700 testów naraz. To jest wskazanie kierunku:
`tests/test_appdata.py` budujący prawdziwe bazy na żywo, w stylu
`tests/test_metadata_csum.py`, ruszyłby liczbę, która w tym repo znaczy więcej niż
każda inna — bo `appdata` jest miejscem, gdzie zła odpowiedź zamienia się w zły
wniosek o człowieku.

## 0.16.0 — sumy kontrolne metadanych: superblock, bitmapy, inody

**Obraz referencyjny nie ma `metadata_csum`.** Redmi 3 z 2016, ext4 bez tej
cechy — i dlatego w docstringu czytnika stało *„parsed but never verified"*. Nie
było czego weryfikować, a narzędzie nie umiało tego powiedzieć. Teraz mówi to
wprost: `status: not_present`. **To nie jest „ok"** — brak sum to nie sukces
kontroli, tylko jej brak, a raport mówiący *„metadane zweryfikowane"* na
systemie plików bez sum byłby dokładnie tym zdaniem, którego to narzędzie nie
wypowiada. Zmiana dotyczy obrazów z Android 9 i nowszych.

**Trzeci stan, nie dwa.** `checksums()` zwraca `ok` / `failed` / **`not_present`**,
i to ostatnie jest najważniejsze. Kształt jest ten sam w każdym kubełku, żeby
konsument czytał `status` i `bad` bez sprawdzania, która gałąź je wyprodukowała.

Nowe `forensic/core/crc32c.py` — crc32c w konwencji e2fsprogs (bez
przed- i po dopełnienia, bo seed przechodzi wprost, a każdy wywołujący w scheme
ext4 prowadzi jedną wartość biegłącą przez kilka buforów). Weryfikowane wektorem
kontrolnym `crc32c(b"123456789") ^ 0xFFFFFFFF == 0xE3069283` oraz **przez
porównanie z e2fsprogs**, nie z samym sobą.

**Dwie własności, które były złe w pierwszej próbie i obie dają wiarygodną złą
liczbę zamiast błędu:**

1. **Suma superblocka nie bierze seeda.** `ext2fs_superblock_csum` to
   `crc32c_le(~0, sb, offsetof(s_checksum))` — obejmuje 1020 bajtów **przed**
   polem sumy i na nim się kończy, więc pola ani nie zeruje, ani nie dokleja.
   Każda inna struktura w formacie jest zasiana, co czyni superblock wyjątkiem
   zamiast regułą. Sto osiem wariantów przeszukanych bez trafienia, zanim
   sprawdzony został kod źródłowy e2fsprogs zamiast mojej pamięci o nim.
2. **`i_extra_isize` liczy bajty poza 128.** `i_checksum_hi` jest pod 0x82
   bezwzględnie, ale test e2fsprogs to `i_extra_isize >= 4`, nie `>= 0x84`.
   Przeczytanie progu bezwzględnie sprawia, że każdy inode wygląda na pozbawiony
   górnej połowy, a każdy z górną połową jest wtedy zgłaszany jako uszkodzony.

**Weryfikacja przed zapisaniem czegokolwiek**, na obrazach budowanych przez
`mke2fs`:

| struktura | wynik |
|---|---|
| superblock | 6/6 dla bloków 1K, 2K, 4K |
| inody | 8/8 (6 realnych + 2 same-zero) |
| bitmapa bloków | zgodna |
| bitmapa inodów | zgodna |
| deskryptory grup | **nie do sprawdzenia tutaj** |

Pusty inode to trzeci przypadek obok zgodnego i niezgodnego: ma zerową sumę z
konstrukcji, e2fsprogs to przyjmuje i tu też. Liczony osobno, żeby nie
napompowywać licznika *zweryfikowanych* inodów.

**Deskryptory grup wymagają bitu `gdt_csum`, który jest osobnym bitem** i którego
ten e2fsprogs nie pozwala ustawić ani przez `mke2fs -O`, ani przez `tune2fs -O`.
Gałąź napisana ze źródła i sprawdzona **tylko kształtem**; test mówi to
wprost, zamiast udawać pokrycie. Czytelnik, który twierdziłby, że zweryfikował
deskryptory, byłby dokładnie tą awarią, na którą ten zestaw poluje.

**Wykrywanie uszkodzeń** — to jest właściwa wartość dodana, bo bitmapa jest
tym, z czego liczy się wolne miejsce i z czego bierze się odpowiedź „czy ten blok
wolny", czyli czy wyrzeźbiony plik można wierzyć. Testy przerzucają **jeden
bajt** w superbloku, w bitmapie i w inode i sprawdzają, że każdy zostaje
złapany. Jeden bajt, bo to najmniejsza możliwa zmiana i najczęstsza: zepsute
bitmapa wygląda dokładnie jak wolne miejsce.

`image_info` raportuje to jako finding, `reporting._csum_line` drukuje w
Markdownie. Weryfikacja jest stdlib-only i nie potrzebuje roota ani e2fsprogs —
`e2fsck -fn` też to robi, ale tam, gdzie go nie ma, ta odpowiedź teraz jest.

`tests/test_metadata_csum.py` (14), w tym porównanie z `dumpe2fs`, wektor
kontrolny, oraz osobno: obraz bez sum to `not_present`, a nie `ok`; i własność
„suma superblocka kończy się przed swoim polem" przypięta testem.

## 0.15.0 — wyciąganie strumieniowe: RAM nie rośnie z rozmiarem dowodu

**Zmierzone na pliku 192 MB w obrazie ext4, ten sam SHA-256 w obu ścieżkach:**

| | przyrost szczytowego RSS |
|---|---|
| `blob = fs.read(path)` → `write_bytes` → `sha256(blob)` | **384,8 MB** |
| `copy_stream(...)` | **24,9 MB** |

Dokładnie 2× rozmiar pliku w starej ścieżce, bo `read_at` buduje `bytearray`
całej długości, a potem `write_bytes` kopiuje drugi raz. W nowej przyrost
odpowiada jednemu chunkowi i nie zależy od tego, czy artefakt waży 10 MB czy
10 GB.

Ścieżka wymieniona wyżej to była dokładnie ta, którą poprzednia tura
certyfikowała w manifeście: najpierw cały plik w RAM, potem zapis, potem hash
z bufora. Poza pamięcią trzymała też plik dłużej niż trzeba.

**Zapis jest atomowy.** Bity lądują w `<nazwa>.part`, gotowy plik jest
`rename`owany na miejsce. `extract_file` wpisuje ścieżkę wyjściową do manifestu
**zanim** czyta bajty, więc plik częściowy pod nazwą końcową byłby wymieniony
w manifeście jako udane wyciągnięcie i znaleziony przez następny przebieg — który
przy istniejącym pliku wraca wcześnie i parsowałby fragment jako całą bazę.
Awaria zostawia więc zero śladów, również po `KeyboardInterrupt`.

**`i_size` to pole w obrazie i może kłamać o gigabajty.** Limit 4 GiB na plik,
przekroczenie daje `complete: False` i status `TRUNCATED`, a nie prefiks udany
jako plik — bo oddanie prefiksu po cichu to ten sam błąd co dopełnianie
krótkiego odczytu, tylko w innym przebraniu.

`Ctx.materialise` też jest strumieniowy. Każdy jego wywołujący chce pliku **na
dysku** dla SQLite, więc trzymanie całego artefaktu w RAM po drodze było kopią
całego pliku bez powodu.

`tests/test_streaming.py` (10): bajt w bajt i zgodność hasha, pamięć ograniczona
chunkiem i nie wielkością pliku, **kolejność offsetów ciągła** (luka w offsetach
to dokładnie ten sam objaw co dziura rzadka, tylko od strony zapisu), brak
pliku częściowego po błędzie i po przerwaniu, przetrwanie wcześniejszego
wyekskstrahowanego pliku przy nieudanym nadpisaniu, `i_size` kłamiący vs limit,
plik rzadki przez moduł, hasz manifestu zgodny z plikiem na dysku.

## 0.14.0 — nieudane odczytanie przestaje być cichą czystą negatywą

Stan bazowy, na obrazie referencyjnym 27 GB i świeżym katalogu roboczym:
**33 checki, 722 asercje, 31 PASS, 2 Niezgodne** — te same dwa co przed turą
(`apps.edl_acquire`, `report.secret_audit`). **119 testów** przechodzi, było 96.
Samotest ext4: 10 wariantów formatu bez zmian (`silent: 0`) plus **10 przypadków
uszkodzonych bajtów**.

**Cztery stany, nie dwa.** Parser ma trzy odpowiedzi dla każdego artefaktu i
`PRESENT` / `ABSENT` / `UNREADABLE` nie są wariantami jednej. Trzecia ginęła,
bo naturalny sposób obsługi wyjątku to złapać go i zwrócić pusty wynik — a
pusty wynik to **wartość**, więc płynie dalej i jest ostatecznie wydrukowana jako
licznik zer. `except sqlite3.Error: return []` jest właśnie tym kształtem.

Nowe `forensic/core/readlog.py` — `ReadLog` plus te cztery słowa. To nie jest
nowy pomysł: czytniki filesystemów niosą `walk_errors` od kilku tur dokładnie z
tego powodu, a `walk_errors` dotarło do `reporting.py`. Teraz ten wzorzec jest
uogólniony, bo jedno nieudane źródło nie może chować się za modułem, który
zwrócił zero.

**`count_rows` zwracał `-1`, a `-1` jest prawdziwe.** `quicklook` budował
`non_empty_tables = {k: v for k, v in counts.items() if v}`. Tabela, której
`count(*)` się nie powiodło, wracała jako `-1`, przechodziła ten filtr i
pojawiała się w raporcie wśród tabel, **które coś zawierają**. Teraz `None`.
`quicklook` ma też `status` i `unreadable_tables`.

**`get(key, 0)` na kluczu celowo pominiętym.** `_whatsapp_type_profile` zostawiał
`starred` nieustawione, gdy zapytanie padło, a `whatsapp.py` czytał
`msgstore.get('starred', 0)` i drukował *„0 oznaczonych gwiazdką"* — twierdzenie o
urządzeniu, na dowodzie, którego nie przeczytano. Teraz `None`, a `_counts_sentence`
rozróżnia sześć stanów; `forwarded` był chroniony, `starred` nie.

**Uciekający `sqlite3.Error` gubił wynik w całości.** `controller.run_module`
łapał `Exception`, drukował linię i zwracał `None`: brak findings, brak eksportu,
nic w `verify.json`. Dziś `TruncatedEvidenceError` i `sqlite3.Error` dostają
własne findingi (`UNREADABLE`, `TRUNCATED`) z notatką, która trafia do
`session.json`. Pozostałe wyjątki wciąż idą w `traceback`, bo błąd w kodzie nie
jest twierdzeniem o dowodzie i nie może zostać wygładzony do findingu.

**Oś czasu niesie własne luki.** `Timeline.read_errors` i `Timeline.complete` —
luka nie może być zdarzeniem, bo zdarzenie deklaruje znacznik czasu i źródło, a
to nie ma żadnego. `login_timeline` przy pustej bazie prefs zostawiał pustą oś
„messenger", która wyglądała jak telefon, na którym nikt się nie logował.
`fb_tokens` mówił „0 dokumentów, 0 tokenów", w tym z bazy, której nie otworzył —
i czytał tę tabelę dwa razy.

**`_probe` w samoteście nie odróżniał ucięcia od zepsutego formatu**, a to jest
dokładnie ten przypadek, który `TruncatedEvidenceError` od początku był
oddzielny. Osobny kubełek.

**10 przypadków uszkodzonych bajtów.** Ta sama czysta kopia z `mke2fs`, uszkodzona
w jednym miejscu: `s_magic`, `s_blocks_count`, deskryptor grup, `bg_inode_table`
poza EOF, `i_mode`, `i_size`, `ee_len` sięgający za koniec, bitmapa bloków,
ucięcie o blok, ucięcie o bajt. Wymaganie jest **jedno**: czytnik nigdy nie może
otworzyć bez błędu i zwrócić pustki. Odrzucenie jest wymagane tylko tam, gdzie
uszkodzone bajty nie da się wiarygodnie odczytać — **wyzerowana bitmapa bloków ma
być przyjęta**, bo bitmapa naprawdę tak twierdzi i to nie jest wymysł czytnika.

Dwie błędy w samej maszynie, warte zapisania:

1. `_offsets_for` liczył offset inoda z `first_data_block + 1`, czyli z bloku po
   superbloku, gdzie jest **tablica deskryptorów**, nie tablica inodów. Trzy
   uszkodzenia lądowały w obszarze deskryptorów, nie zmieniały niczego, a
   samotest raportował je jako *przyjęte z trzema wpisami w katalogu root*.
   Uszkodzenie, które trafi w wolne miejsce, jest nieodróżnialne od czytnika,
   który je obsłużył.
2. `ee_len` pisany pod `+0x28 + 4`, czyli do `eh_max`. Rekord zaczyna się 12 B za
   nagłówkiem extenta, więc `ee_len` jest o 4 B dalej.

Testy: `tests/test_read_errors.py` (17) — cztery stany, `count_rows` → `None`,
`starred` niezerowe, uciekający `DatabaseError` zapisany, a `TypeError` wciąż
traceback; oraz 6 przypadków w `tests/test_ext4_selftest.py`. Sprawdzone, że
`count_rows` test pada na starej implementacji z `-1`.

## 0.13.0 — integralność dowodu: obraz ucięty przestaje udawać czytelny

Stan bazowy, zmierzony na obrazie referencyjnym 27 GB i na **świeżym katalogu
roboczym**: **33 checki, 722 asercje, 31 PASS, 2 Niezgodne** — dokładnie te same
dwa co przed tą turą (`apps.edl_acquire`, `report.secret_audit`), zmierzone przez
`git stash` na tej samej bazie. To zmiana w tym, **co narzędzie potrafi powiedzieć
o swojej własnej wejściu**, nie w tym, co znajduje. Wszystkie 90 testów
przechodzi, samotest ext4 nadal `silent: 0`.

> Uwaga o metodzie: te checki **nie są hermetyczne** — `report.secret_audit`
> liczy pliki w `work/<case>/extracted` i `cache`, więc liczba zależy od tego,
> co poprzednie przebiegi tam zostawiły. Dlatego porównanie robione jest na
> świeżym `--workdir` po obu stronach. Wpis 0.12.0 podaje „35 checki, 730
> asercji, 35/35 PASS", a case ma 33 checki i dwa od lat nieprzechodzące —
> ta liczba nie odpowiadała rzeczywistości i nie należy jej powtarzać.

**Najpoważniejsza rzecz w tej turze: obraz ucięty wyglądał jak czytelny.**
`_BlockCache.get()` dopełniał krótki `pread` zerami do pełnego bloku
(`data + b"\0" * (self._bs - len(data))`). Ponieważ `read_at()` przycina wynik do
rozmiaru zadeklarowanego w inode, plik, którego bloki danych leżały za końcem
pliku, wracał jako bufor **dokładnie zadeklarowanej długości**, pełen zer, bez
żadnego wyjątku. `extract_file` haszował ten bufor i wpisywał hash do manifestu.
Manifest poświadczający SHA-256 zmyślonych bajtów jest gorszy niż brak
manifestu.

Pomiar na uciętej kopii obrazu testowego — plik zadeklarowany na 4096 B, którego
extenty leżą za końcem pliku:

| | przed | po |
|---|---|---|
| `read()` | 4096 B zer | `TruncatedEvidenceError` |
| zgodność z prawdziwą treścią | 11/4096 B | — |
| hash w manifeście | tak, z zer | nie |

Potwierdzone przez porównanie obu implementacji na tych samych bajtach
(`/tmp/opencode/ev/check.py`): stary kod zwraca `4096 bytes, all-zero=True`,
nowy rzuca `TruncatedEvidenceError`.

**Brakujące dane to nie brak danych.** Ucięcie **poniżej** metadanych dawało
`KeyError`, który każdy moduł renderuje jako *„Brak ścieżki"* — czystą
negatywę. Nie jest to czysta negatywa: plik tam był i nie da się go odczytać.
`extract_file` ma teraz trzy stany w manifeście: `PRESENT`, `ABSENT`,
`TRUNCATED`. Ucięty plik **nie** dostaje `output` ani `sha256` — bo nie ma czego
poświadczać.

**`TruncatedEvidenceError` nie dziedziczy po `Ext4Error`.** Moduły łapią
`Ext4Error`, żeby powiedzieć *„to nie jest ext4, który umiem czytać"*. Gdyby
ucięcie było podklasą, jeden `except` zjadłby brak dowodu i zgłosił zepsuty
format dla filesystemu, którego pierwsza połowa jest w pełni czytelna. Te dwie
odpowiedzi są przeciwne i nie mogą się zlać.

**Nadmiar na końcu pliku to nie ucięcie.** Referencyjny obraz ma 27 577 531 904 B
w pliku przy 27 577 507 840 B zadeklarowanych przez superblock — 24 064 B
więcej, bo kopia partycji w obrazie całego dysku. `Ext4.truncated` liczy
`max(0, declared - available)`, więc nie ma fałszywego alarmu na obrazie, na
którym to narzędzie pracuje.

**`verify` nigdy nie otwierał obrazu, żeby zrobić SHA-256.** `runner.py` robił
`sha = sha or case.get("image_sha256")` i wkładał tę wartość do podsumowania,
jakby przebieg ją potwierdził. `image_sha256` w case jest **twierdzeniem**, nie
wynikiem. Teraz `EvidenceIdentity` porównuje twierdzenie z plikiem, który
przebieg właśnie czyta, i raportuje jeden z czterech stanów — `PASS`, `FAIL`,
`UNVERIFIED` (nie ma z czym porównać), `NOT_CHECKED` (jest twierdzenie, ale nie
przeliczono). *„Nie sprawdzono"* i *„sprawdzone i OK"* nie mogą brzmieć tak samo.

SHA-256 nie jest liczone domyśnie: referencyjny obraz hashuje się **2m51s**
(27 GB, ~160 MB/s), a `stat` jest darmowy. Rozmiar sprawdzany jest zawsze i
za każdym razem; hash tylko gdy poprosi o to `--param rehash=true`. `FAIL` przy
niezgodności rozmiaru lub hasza **zastępuje** werdykt modułu — 33/33 checki
przechodzące na niewłaściwym obrazie to gorszy raport niż 0/33 na właściwym.

Ten sam brak z drugiej strony: `report.py` podpadał do hasha z case, gdy moduł
`image_info` nie był uruchomiony, i prezentował go tak samo jak policzony.
Teraz pole `sha256_source` mówi wprost `obliczony` / `z case`.

**Kolizja nazwek: dwa źródła, jeden plik.** `safe_name()` spłaszczał ścieżkę
podstawieniem, więc `/a/b` i `/a_b` dawały obie `a_b`. Drugi extraction
nadpisywał pierwszy, a manifest wymieniał dwa różne SHA-256 dla jednego pliku na
dysku. Istniejący test `test_distinct_paths_do_not_collide` **przechodził** —
sprawdzał `/data/com.example/x` przeciw `/data/com/example/x`, co rozjeżdża się
dzięki kropce w `com.example`, a nie dzięki temu, że kolizja jest obsłużona.
Nazwa to teraz spłaszczenie **plus digest ścieżki**, a `unique_names()` nie polega
na 48 bitach marginesu: sprawdza i dokleja porządkowy sufiks. Ta sama wada była
w `Ctx.materialise`, z własną wersją podstawienia — teraz oba miejsca dzielą
`forensic/core/naming.py`.

**Druga dziura w tym samym miejscu: plik rzadki (`sparse`) był ucinany po cichu.**
`read_at()` przycinał wynik do `i_size`, a potem **konkatenował** tylko te
extenty, które istnieją. Bufor wychodził krótszy niż deklarowany rozmiar pliku i
**bez żadnego wyjątku**.

Nie jest to teoria. Baza SQLite z `page_size=4096` i małą ilością danych ma
niezapisane strony w środku — plik na dysku jest rzadki. W obrazie wewnętrzne
trzeba jest rzadkie:

| | przed | po |
|---|---|---|
| `i_size` w inode | 16384 | 16384 |
| bloki pokryte extentami | 8 z 16 | 8 z 16 |
| `read()` | **8192 B, bez błędu** | 16384 B |
| zgodność SHA-256 z plikiem | **nie** | tak |
| `sqlite3` na wyniku | `database disk image is malformed` | czyta poprawnie |

To samo zgłoszenie dotyczyłoby zepsutej bazy. Do tego `Ctx.materialise()`
zapisywał ten skrócony bufor na dysk jako „plik”, więc krótsza treść stawała
się trwała. `debugfs dump` na tym samym obrazie daje poprawne 16384 B — czyli
e2fsprogs, referencja, z którą czytnik jest porównywany, robi to inaczej.

**Dwa rodzaje braków wyglądają w kodzie tak samo i wymagają przeciwnego
postępowania.** Brak *fizyczny* — blok nie ma go w pliku — to brak dowodu i
`TruncatedEvidenceError`. Brak *logiczny* — blok wewnątrz `i_size`, którego żaden
extent nie mapuje — to **dziura rzadka**, i format mówi, że czyta się jako zera.
Wypełnianie jej jest tu poprawne; zgłaszanie jako nieczytelną odrzucałoby połowę
plików rzadkich na prawdziwym `/data`. Buffer jest więc rozmiaru żądanego, a
extenty zapisuje się do niego **pozycyjnie**. `tests/test_sparse_holes.py` (6)
pilnuje obu kierunków naraz, w tym że dziura nie jest uznana za ucięcie i że
`hole_bytes()` nie jest stałą — plik bez dziur zgłasza zero.

`hole_bytes()` liczy je na żądanie, a nie zapamiętuje z ostatniego odczytu:
licznik „brakowało w poprzednim wywołaniu” myli się, gdy dwa moduły czytają
różne pliki, a ten tool robi to non stop.

**Nazwy artefaktów się zmieniły** (`data_system_lock_settings.db--682f455a1c70`).
Stabilne między przebiegami — powtórzenie case'u nie zmienia nazw, do których
odwołuje się wcześniejszy raport — ale inne niż poprzednio, więc wyeksportowane
pliki ze starych przebiegów mają stare nazwy i nie zostaną nadpisane.

Nowe: `forensic/core/evidence.py` (`EvidenceIdentity`, `TruncatedEvidenceError`,
`read_exact`, `sha256_file`), `forensic/core/naming.py`.
`sha256_file` przeniesiony z `image_info`, który teraz go re-eksportuje —
akwizycja, `newcase` i `verify` potrzebują go wszystkie i żaden nie powinien sięgać
do innego modułu po niego.
Testy: `tests/test_truncated_evidence.py` (13) — ucięty o 1 B, o blok, o
metadane, o extent; oraz brak zera udającego plik i brak fałszywej czystej negatywy.
`tests/test_sparse_holes.py` (6) — plik rzadki, pozycjonność odczytu, dziura
nie jest ucięciem. Łącznie 96 testów, było 73.

## 0.12.0 — menu: dwa ekrany, prawdziwa dwujęzyczność, ASCII zamiast `ł=?`

Stan bazowy: **35 checki, 730 asercji, 35/35 PASS** — bez zmian, to zmiana
wyłącznie prezentacji.

**Źródło `ł=?` jest w rendererze, nie w tekście.** `safe()` w UI transkribowało
przez `NFKD` i odrzucało znaki łączące. To obsługuje dziewięć z dziesięciu
polskich liter i **zawodzi na `ł`** — `ł` nie ma rozkładu, bo to osobna litera,
a nie `l` z kreską — więc warunek „same ASCII" nie zachodził i `safe()`
wypisywało `?`. To samo dotyczyło **każdego znaku ramki**: `─ │ ╭ ╮ ╰ ╯` również
nie mają rozkładu, więc ramka w frontendzie `curses` składała się ze znaków
zapytania. Nowa `forensic/core/text.py` ma litery wypisane w tabeli — to
definicja, nie obejście: `ą→a` to konwencja, którą sami wybraliśmy.

**Kolumny przestały się rozjeżdżać.** Dopełniano `len()` znakiem, a potem
transkribowano przy rysowaniu. W UTF-8 obie jednostki to jedna kolumna, więc
zgadzały się — aż do komórki wymagającej transkrypcji, kiedy komórka
najpierw dostawała spacje, a potem kurczyła się o znak. Każda kolumna
zawierająca `ł` przestawała się zgadzać. Teraz mierzymy **po transkrypcji**
(`text.width`, `text.pad`), a wielokrotek `…` wchodzi do komórki już
przetranskrybowanej.

**Osobno, i to jest najważniejsza część tej tury: chrome transkrybujemy,
dowodów nie.** Przeprowadzone przez `render_table` i `safe()` trafiły trzy miejsca,
w których to psuło dane:

1. **tabela podsumowania weryfikacji** — drukuje to, co asercja faktycznie
   odczytała. Transkrypcja zamienia `zażółć.txt` na `zazolc.txt`, czyli
   zgłasza nazwę pliku, **którego w obrazie nie ma**. To jest dokładnie
   odwrotność zadania tego narzędzia, więc dostało `transliterate=False`.
2. **pasek edycji w `curses`** — `safe()` na tym, co użytkownik właśnie wpisał.
   Wpisanie ścieżki `zażółć.txt` do `extract_file` wyekstrahowałoby
   `zazolc.txt`.
3. **panel szczegółów w `curses`** — tytuły findings i wartości parametrów, czyli
   to, co odczytano z obrazu.

Panele interfejsu przechodzą transkrypcję (`chrome()`), dane nie (`put()`).
Raport na dysku zachowuje polskie znaki w całości, bo plik UTF-8 to nie terminal.

**Menu przebudowane, bo było nieczytelne z powodów niezależnych od kodowania.**
Kategorie i akcje były w jednej płaskiej liście numerowanej 1–11, z akcjami
wciętymi o dwie spacje i dzielącymi tę samą sekwencję; nic nie mówiło, co jest
czym, więc najszybszym ruchem nowego użytkownika było sprawdzanie liczb po
kolei. Teraz: **cyfry dla kategorii, litery dla akcji**, w dwóch oznaczonych
blokach. Liczby modułów we własnej wyrównanej kolumnie zamiast ``(11)`` doklejone
do etykiety. Ścieżki obrazu i katalogu roboczego na osobnych wierszach i
nigdy nie przycięte — twarda szerokość kolumny skróciła katalog roboczy do
`/path/to/work/redmi3` bez końca, czyli do ścieżki, która wygląda
poprawnie i nigdzie nie prowadzi.

**Przełącznik języka w ogóle nie działał.** Menu pokazywało literę `l`, a
dispatcher porównywał z `"lang"` — `l` nie robiło nic. Klucz i nazwa wewnętrzna
są teraz w jednym wierszu tabeli, żeby nie mogły się rozjechać znowu.

**Usunięto pary językowe w etykietach.** `Weryfikacja (case) / Verify` i
`Język / Language → pl` wkładały jeden język w etykietę drugiego: polski
czytelnik widział angielski, angielski — polski, a żaden nie wiedział który jest
który. Cały interfejs jest w jednym języcu, przełączanym, a menu mówi w linii
stanu który.

**`?` to ekran, nie wzruszenie ramion.** Odpowiedź na `?` wypisywała słowo
„Pomoc", potem słowo „Skróty" i przechodziła do następnego pytania w tym samym
miejscu. Teraz otwiera ekran z klawiszami, wyjaśnieniem bloków i z tym, czego
narzędzie nie robi. Dodatkowo `ask()` **przestał połykać `?`**: prompt, który nie
umie się wyjaśnić, powinien raz powiedzieć i zejść z drogi — a ekran, który umie,
teraz ma ten klawisz.

**Kolumna `id` zniknęła z listy modułów.** Jest tym, co wpisujesz w wierszu
poleceń, więc jest przydatna — i bezużyteczna dla kogoś, kto wybiera, co
uruchomić, bo czyta tytuły. Zabierała 16 kolumn, których potrzebował opis, a
opis właśnie mówi, co moduł robi. Identyfikator nadal jest, we własnym ekranie
modułu.

**Oba frontendy mają teraz ten sam kształt i te same skróty.** Dwa frontendy
oferujące dwie różne kolejności to ten sam problem co dwie różne mapy klawiszy:
mięśń wytrenowany na jednym myli na drugim.

**Menu nie znało szerokości terminala i to nigdy nie było sprawdzone.** Ramka
była na sztywno 76 kolumn. W terminalu 60-, 40- i 30-kolumnowym **każda linia
zawijała się po miękku** i druga kolumna wiersza lądowała pod pierwszą, więc
dwa bloki, które miały być czytelne obok siebie, stawały się jedną zwijaną
kolumną. Szerokość bierze teraz z `os.get_terminal_size()`, a wszystko, co nie
mieści się, jest **przycinane ze znakiem**: etykiety, kolumna liczników,
podpowiedzi akcji, stopka i nagłówek bloku. Podpowiedź akcji próbowała najpierw
zmierzyć miejsce od **kolumny etykiet** zamiast od własnej etykiety, przez co
krótka etykieta pożyczała miejsce i `-> odsloniete` kończyło się jedną kolumnę
za terminalem.

Sprawdzone przez przeprowadzenie menu w pseudo-terminalu przy 140, 120, 100,
80, 72, 64, 56, 48, 40, 32, 24 i 20 kolumnach: **żadna linia nie przekracza
szerokości**. Pod 20 kolumnami celowo zostaje jedna zawinięta linia — alternatywą
byłoby cięcie każdej etykiety do szesnastu znaków i lista, której nie da się
przeskanować. Ramka znika poniżej 40 kolumn, bo to część, która nie mieści się
najwcześniej.

**Dwie rzeczy, których nie zauważyłem, sprawdzając ręcznie.** `banner()` dostał
parametr szerokości w `menu.py`, a nie w `base.py`, więc menu wywracało się z
`TypeError` przy pierwszym uruchomieniu — mój własny test przez pseudo-terminal
zwracał pustkę i wyglądał jak „brak outputu", a nie jak błąd. I w panelu `curses`
ścieżka oraz podpowiedź były **ucięte bez żadnego znaku**, że są ucięte:
`/path/to/redmi3_userdata_full_v` czyta się jak cała ścieżka. Teraz
`fitted()` oznacza cięcie trzema kropkami.

Stan planu: bez zmian. PLAN.md 8.16 — pozostają squashfs i dekompresja
LZ4/HZMA, czekające na obraz z innego telefonu.

## 0.11.0 — wyrzeźbienie: 52 189 nazw i 3 kandydatów treści

Stan bazowy: **35 checki, 730 asercji, 35/35 PASS** (było 34 checki, 686).

Krok 3 z trzech planu 7.5 — i krok, przed którym plan najbardziej się
obawia: *„carving z klastra bez metadanych jest z natury osłabiony dowodowo i
musi być tak opisany w raporcie, inaczej buduje fałszywą pewność"*. Moduł `carve`
robi dwie rzeczy i **nie udaje, że to jedna**.

### 52 189 nazw usuniętych plików — i nie z przejścia po katalogach

ext4 **scala** wpis żywy z wpisami usuniętymi po nim. Na obrazie referencyjnym
`/media/0/MIUI/Gallery/cloud/.cache` ma rekord dla `micro_thumbnail_blob.1`
długi na **3916 B**, który połyka resztę bloku, a wszystkie nazwy usunięte z
tego katalogu leżą w jego wnętrzu. Przejście po `rec_len` znajduje **286**;
przesunięcie okna po każdym bajcie każdego bloku katalogowego znajduje
**51 903** więcej. To ta sama technika, którą używa carver — i dlatego `fls -d`
zgłasza dziesiątki tysięcy tam, gdzie przejście po łańcuchu zgłasza setki.

Rozdział jest istotą wyniku, nie ozdobą:

- **286 w łańcuchu, z wyzerowanym numerem inoda** — to, co jądro zapisuje przy
  unlink. Nazwa należała do tego katalogu, a inoda nie ma, więc nic nie da się
  do tej nazwy dołączyć przez pomyłkę.
- **51 903 tylko w oknie** — nieosiągalne z łańcucha, więc ext4 nadpisał
  przestrzeń, która je opisywała. **Nazwa** jest pewna. **Numer inoda** w rekordzie
  mógł już należeć do innego pliku, więc rozmiar, uid i czasy za nim nie są
  dowodem o usuniętym. Każdy rekord ma własne `metadata_trust`.

Że te 286 są osiągalne łańcuchem, jest własnością tego obrazu, nie formatu.
Wpis usunięty **po** tym pochłaniającym jest w tej samej pozycji i równie
niewidoczny — i to właśnie buduje fixture ręczny w samoteście (blok 4370
obrazu 64 MiB: rekord pochłaniający 1000 B z trzema wpisami w środku, dwoma
o zerowym numerze inoda). Podział został **zmierzony**, nie przemyślany, a
fixture złapała przy okazji błąd filtra okna, który odrzucał zerowy numer
inoda — czyli zapisałby się ślepo na dokładnie tych rekordach, którym najwięcej
ufamy.

**`tsk_crosscheck` zgłasza „51 924 niepodlinkowanych wpisy" jako jedną liczbę
od tury 8. Nigdy nie była to jedna rodzaj rzecz.** `fls -d` uznaje rekord za
usunięty, gdy jego numer inoda wskazuje teraz obiekt innego typu (31 022 z nich
opisuje jako przydzielone ponownie); nasze rozróżnienie to łańcuch kontra okno.
Liczby stoją obok siebie i nie są uśredniane — różnica w zasadach, nie błąd.

### 3 kandydatów treści, każdy ze stopniem dowodu

Trzy stopnie: `validated` (struktura za sygnaturą przeszła do swojego
terminatora albo przeliczono sumę), `magic` i `weak`. Kandydat ucięty końcem
luki jest **przerwany**, nie mniejszym plikiem. **Odrzucono 143 sygnatury JPEG**,
które nie przeszły walidacji — liczba w raporcie, bo wyrzeźbienie, które nigdy
nie mówi, ile razy powiedziało „nie", nie da się ocenić, gdy mówi „tak".

**Co ta przestrzeń zawiera.** Największa ciągła masa bajtów niezerowych w
przestrzeni wolnej obrazu referencyjnego to **usunięty obraz OAT z `/system`**
(`oat\n045`, nagłówek ELF, struktury ART), plus dane lokalizacyjne ICU i fragment
XML. Nic z tego nie jest dokumentami użytkownika. `oat` trafił do tabeli
sygnatur właśnie z powodu tego znaleziska; obraz DEX wewnątrz kontenera ART
świadomie nie, z zapisanym powodem.

### Cztery błędy, które złapał samotest

1. **Odczyt za końcem luki zwracał zera**, więc ucięty PNG przegrywał sumę i
   był raportowany jako **nic** — jedyna odpowiedź, której nie wolno dać o
   sygnaturze, która naprawdę tam była.
2. **Przestrzeń kończyła się na bloku, a nie na luce** — każdy plik
   wieloblokowy był raportowany jako przerwany.
3. **Po `SOS` dane entropijne JPEG-a** były przechodzone tak, jakby miały
   długości segmentów; parser rozjeżdżał się na pierwszym `FF` w danych
   obrazu i odrzucał plik doskonały.
4. **Widok na lukę dostawał przesunięcie względem bloku zamiast względem luki** —
   każdy kandydat poza pierwszym blokiem luki był walidowany wobec
   niewłaściwych bajtów, co wygląda dokładnie jak obraz bez niczego.
   Plus: `zlib` w trybie gzip oczekuje **całego** strumienia z nagłówkiem;
   podanie mu samych danych deflate daje *incorrect header check* na pliku
   doskonałym. I: `e_machine` w ELF czytany big-endian daje 46848 zamiast 183 —
   odrzucony prawdziwy traf, najdroższy z możliwych błędów wyrzeźbienia,
   bo nic nie jest zgłaszane i nic nie wygląda źle.

Samotest pisze prawdziwe pliki (PNG z poprawnymi sumami chunków, prawdziwy gzip,
plik tekstowy bez sygnatury, plik będący sygnaturą PNG za którą są śmieci),
usuwa je `debugfs -w -R rm` i sprawdza, że PNG i gzip wracają **bajt w bajt**,
a tekstu i oszusta wyrzeźbić się nie da.

### Zmiana w czytniku, która wyszła z tego

`unlinked_entries()` **nie skanuje katalogu startowego**, bo `walk()`
zwraca dzieci, a nie katalog, z którego wyszło. Na obrazie referencyjnym to
jeden blok na 20 653 i przeoczenie było niewidoczne w sumie; na systemie
plików, w którym usunięcia działy się w katalogu głównym, to cała różnica
między znalezieniem nazw i nieznalezieniem żadnej. Fixture to pokazała.

### Czego świadomie NIE zrobiono

- **Nie przypisano kandydatów do nazw.** Skąd wziąć parach? ext4 usunął inod i
  wpis katalogowy; nie ma łącznika i **żadnego się nie zmyśla**. Moduł podaje
  `files_recovered: 0`, `candidates_attributed_to_files: 0`,
  `candidates_have_names: False` **w polach**, nie w zastrzeżeniu tekstowym.
- **Nie wypisano ani jednego bajtu odzyskanego pliku.** Lista kandydatów to
  zakresy do obejrzenia przez człowieka, nie pliki.
- **Nie weryfikowano sum metadanych** filesystemu — to osobna sprawa.
- **Nie dodano formatów bez ogólnodostępnej sygnatury.** Formaty zastrzeżone
  (FB, Messenger) i wewnętrzne struktury ART pominięte, bo odkrycie byłoby
  twierdzeniem bez podstawy; powody w `core/carve.py`.
- **`undark` nadal odłożone** (GPL-3.0), powód z tury 15 bez zmian.

Stan planu: 8.1, 7.2, 8.2, 7.3, 7.4 (EROFS + F2FS), **7.5 wszystkie trzy
kroki** gotowe. Zostaje squashfs i dekompresja LZ4/HZMA. PLAN.md 8.15.

### Gdzie to się zatrzymuje, i dlaczego

Praca zatrzymuje się tu **świadomie**, nie z braku czasu. Zostają dwie pozycje
i obie czekają na to samo: **obrazu z innego telefonu**.

Wszystko zmierzone w turach 16–18 pochodzi z jednego urządzenia — Redmi 3 z
2016 roku, odczyt EDL. Formaty, o których mowa, zostały zbudowane przez `mkfs`
w tej sesji i zweryfikowane wobec `dump.f2fs` i `dump.erofs`. To sprawdza, **czy
zdolność działa**; nie sprawdza, **czy znajduje coś w prawdziwym dowodzie**.
Granica, którą plan nazwał „przewidziane, nie sprawdzone", pozostaje otwarta dla
kompresji, `flexible_inline_xattr` i zawiniętego NAT.

- **squashfs** — zweryfikowalne w całości (`mksquashfs` i `unsquashfs` są na
  hoście, czytnik powstałby jak EROFS w turze 13). Odkładane, bo nie ma obrazu
  z ROM-u, na którym squashfs w ogóle występuje, a kolejny interfejs formatu
  napisany na zmyśle kosztowałby bezpośredniej korzyści.
- **dekompresja LZ4 / HZMA** — najpierw **decyzja polityczna**: `zlib` ma gzip i
  deflate, `lzma` ma kontener XZ/LZMA2, ale surowego LZ4 nie ma ani w stdlib,
  ani jako program na tym hoście. To wybór między złamaniem zasady „tylko
  stdlib" a wołaniem binarki jako procesu (wzorzec z `edlclient`). Bez obrazu
  skompresowanego `/system` nie da się odpowiedzieć, ile treści w ogóle jest
  skompresowane, czyli czy wplyw jest większy niż koszt zależności.

**Co by to zmieniło:** jeden zrzut `/system` lub `/data` z telefonu z lat
2019–2026, na którym widać, że format jest skompresowany.

**Co nie zależy od takiego zrzutu i jest już zrobione:** trzy zdolności, które nie
czekają na nic — czytnik EROFS, czytnik F2FS, przestrzeń nieprzydzielona z
carvingiem. Gdyby taki zrzut się pojawił, to właśnie te trzy moduły są jedynymi,
które otworzą plik z takiego urządzenia, a nie dekompresja. Brak kompresji
oznacza mniej odczytanych plików, nie brak dostępu.

Kolejny krok przy następnym zrzucie, w kolejności: `blockmap` i `find_string`
dla F2FS (7.4 krok 4, otwarte od tury 16) → dekompresja, jeśli zrzut pokaże,
że jest istotna → squashfs, jeśli zrzut pokaże, że jest na partycji.
PLAN.md 8.16.

## 0.10.0 — przestrzeń nieprzydzielona: 7.5 krok 2 z 3

Stan bazowy: **34 checki, 686 asercji, 34/34 PASS** (było 33 checki, 606).

Tura 14 policzyła usunięte inody i wykazała, że ich treści **nie da się
wskazać przez inod** — ext4 czyści mapę bloków przy unlink, więc wszystkie 378
z zachowanym rozmiarem mają `i_blocks = 0`. Bajty są na wolumenie, w blokach,
które alokator oddał. Ten krok je znajduje i mierzy. **Nie odzyskuje niczego.**

### Wynik na obrazie referencyjnym

- **2 494 484** nieprzydzielonych bloków = **9,52 GiB** (10 217 406 464 B)
- **30 107** luk, najdłuższa **967** bloków (3,78 MiB), zaczyna się w bloku 1 074 732
- podział luk: 6 003 jednoblokowe, 8 216 po 2–8, 10 082 po 9–128, 5 806 po 129–1024
- **99,971% to zera** (próbka 4%); niezerowości ok. **723 bloki, 2,82 MiB**
- **0** plików i **0** nazw odzyskanych — i to zapisane w polach, nie domyślane

### Trzy liczniki, które powinny być równe, a nie są

Bitmapy bloków: **2 494 484**. `s_free_blocks_count`: **2 494 472**.
Suma 206 deskryptorów grup: **2 510 845**. Użyto bitmap, bo to z nich przydziela
alokator; rozjazd zgłoszony, nie zaciemniony.

**Trzy niezależne czytelniki mówią to samo.** `dumpe2fs` zgadza się na
dziesięciu obrazach syntetycznych. `blkls` oddaje 10 217 406 464 B — tyle samo
co nasz zrzut, co do bajtu. `e2fsck -fn` liczy 2 494 484 i wypisuje
`Free blocks count wrong (2494472, counted=2494484)`. Niespójny jest tylko
licznik w superbloku, a obraz ma `RECOVER` i `errors = 2`, więc zapisano go przy
nieczystym zamknięciu.

### Sprawdzone, nie założone: w przestrzeni nic żywego nie ma

ext4 oznacza metadane jako przydzielone w tej samej bitmapie, więc jej
odwrócenie zostawia je poza zakresem z konstrukcji. Ale „z konstrukcji” to
argument, więc moduł składa **138 685** bloków metadanych z samych struktur —
superblok, tablica deskryptorów, bitmapy i tabele inodów 206 grup, kopie
superbloków w 11 grupach sparse_super, 32 768 bloków journalu — i liczy
przecięcie z przestrzenią wolną: **zero**.

Grupy sparse_super policzone wg reguły „0, 1 i potęgi 3, 5, 7”, sprawdzonej z
listą `dumpe2fs` (1, 3, 5, 7, 9, 25, 27, 49, 81, 125 — plus grupa 0 z
superblokem głównym). W superbloku **nie ma pola `sparse_super`**, jest tylko
flaga cechy `SPARSE_SUPER`; czytnik szukający tam mnożnika znalazłby nic.

### `BLOCK_UNINIT`: trzy stany, bo flaga i bit cechy żyją osobno

Pierwsza wersja miała **wyłączać** te grupy z przestrzeni, wnioskując, że bitmapy
nikt nie utrzymuje, więc nie ma co odwracać. To było złe i zostało poprawione
po zmierzeniu: `dumpe2fs`, `blkls` i ten czytnik liczą je **razem**, bo tak
właśnie rozumie je alokator. Wyłączenie dałoby liczbę inną niż oba narzędzia
porównawcze i zaniżyłoby przestrzeń.

Rozróżnione trzy stany, z których każdy jest zmierzony:

1. **cecha on, flagi grup oni** (`mke2fs -O uninit_bg` na blokach 1024 B) —
   flagi znaczą, co znaczą: wolne z definicji;
2. **cechy brak, flagi są** (świeży wolumen 64 MiB, bloki 1024 B, bez opcji) —
   mke2fs stawia `BLOCK_UNINIT` w grupach 4 i 6, a bitu `uninit_bg` nie ustawia.
   Bez cechy jądro takich grup nie traktuje jako niezainicjalizowane, więc ich
   bloki są wolne **z pomiaru**;
3. **cecha on, żadna grupa nie zgłoszona** — obraz referencyjny; wszystkie
   bitmapy zapisane, każdy wolny blok wolny z pomiaru.

Liczba ta sama we wszystkich trzech, bo odwrócenie zerowej bitmapy i tak znaczy
„cała grupa wolna”. **Uzasadnienie różne**, a raport nie może twierdzić pomiaru,
którego nie zrobił. Osobno wykrywany stan czwarty: grupa z flagą
`BLOCK_UNINIT` i niezerową bitmapą — sprzeczność, w której zaufanie flagzie
wyrzuca prawdziwe dane, a zaufanie bitmapie przyjmuje system, który sam mówi,
że bitmapy nie ma. Raportowane jako `critical`.

### `blkls` zgadza się co do liczby, nie zawsze co do zbioru

Samotest porównuje obie rzeczy, bo porównanie samych liczb **ukryłoby
różnicę**. Liczba zgadza się na wszystkich dziesięciu wariantach. Zbiór zgadza
się na wszystkich czterech wariantach o blokach 4096 B i różni się o 1–5
bloków na mniejszych.

Różnica zdiagnozowana, a nie zgadywana: oznaczając każdy blok obrazu i odczytując
znaczniki z wyjścia `blkls`, widać **który** blok cicho znika. `blkls` wyłącza
bloki, które `ext2fs_block_getflags()` klasyfikuje jako metadane **niezależnie od
bitmapy**, a przy `flex_bg` ta klasyfikacja miesza bezwzględny adres bitmapy
grupy z numerami bloków. Ta sama funkcja ma w kodzie komentarz przyznający
błąd o jeden tam (`XXX There appears to be an off-by-one discrepancy between
bitmap offsets and disk block numbers`).

Dlatego moduł **nie pożycza** tej heurystyki, tylko robi własne sprawdzenie
metadanych — eksplicytne i niezależne od TSK.

### Nakładanie przestrzeni na metadane: zgłoszone, nie wyłączone

Na obrazach budowanych `mke2fs` nakładanie wynosi 1–7 bloków i **za każdym razem
leży na ostatnim bloku zakresu metadanych** — to ostatni blok journalu, o
którym ten czytnik i `e2fsck -fn` mówią różne rzeczy, przy czym `e2fsck` uznaje
taki obraz za czysty. Liczba wolnych bloków zgadza się mimo tego z `dumpe2fs` i
`blkls`, bo bitmapy czytane są identycznie. Raportowane jako `warn` z podanymi
numerami; nakładanie **wewnątrz** zakresu byłoby `critical` i jest w samoteście
wymuszane jako nieobecne.

### Próba treści: 4% systematycznie, z numerami bloków

Przestrzeń 9,52 GiB czyta się w 48 MB/s, czyli pełny przebieg to ~3,5 minuty
przebiegu weryfikacji. Domyślnie próbka **systematyczna co 25. blok** (4%),
żeby trafiła w każdą lukę, a nie w środek pierwszej. W niej **99,971% zer**,
29 bloków z niezerami → szacunek **723 bloków, 2,82 MiB**. Próba jest w raporcie
nazwana próbką, podaje przeczytany ułamek przestrzeni i **numery bloków z
trafieniami** (64 domyślnie), żeby następny krok nie musiał czytać 9,51 GiB
jeszcze raz. `scan=full` czyta wszystko i mówi to wprost.

### Zrzut: opcjonalny, z sumą

`Ext4.dump_unallocated()` to odpowiednik `blkls` — wolne bloki po kolei,
nagłówkowo. 9,51 GiB na obrazie referencyjnym, więc **na żądanie** (`dump=true`),
z liczbą bloków, rozmiarem i SHA-256 liczonymi w trakcie pisania, żeby raport
mógł zidentyfikować zrzut bez jego przechowywania.

### Czego świadomie NIE zrobiono

- **Nie wyrzeźbiono żadnego pliku.** Krok 3 jest osobną pracą: sygnatury,
  nagłówki i stopki, kompresja, i — jak plan zapowiada — opis osłabienia
  dowodowego, bo wyrzeźbienie z klastra bez metadanych nie jest odtworzeniem
  pliku. Moduł podaje `files_recovered: 0` i `names_recovered: 0` w polach, nie
  w zastrzeżeniu tekstowym, żeby raportujący nie mógł tego pominąć.
- **Nie przypisano bajtów do plików.** Nie wiadomo, który blok należał do
  którego pliku i nie da się tego wiedzieć: `i_blocks` usuniętego inodu jest
  zerowe, a nazwy nie ma nigdzie poza blokami katalogowymi.
- **Nie wykryto treści, tylko jej obecność.** Liczenie zer i niezerów nie
  rozróżnia obrazu, bazy SQLite ani fragmentu tekstu. To granica kroku 2.
- **`undark` nadal odłożone** (GPL-3.0), z powodu z tury 15 — bez zmian.
- **Nie sprawdzono obrazu z urządzenia po odmontowaniu.** Wszystko zmierzone na
  obrazie referencyjnym i na dziesięciu syntetycznych.

Stan planu: 8.1, 7.2, 8.2, 7.3, 7.4 (EROFS + F2FS), 7.5 kroki 1 i 2 gotowe.
Zostaje **7.5 krok 3** (carving) oraz squashfs i dekompresja LZ4/HZMA.
PLAN.md 8.14.

## 0.9.0 — F2FS: czytnik `/data` z obecnego Androida

Stan bazowy: **33 checki, 606 asercji, 33/33 PASS** (było 526).

F2FS to format, w którym obecny telefon trzyma `/data`. Do tej pory był
rozpoznawany po magice i odrzucany — a `/data` to partycja, na której są
dowody, więc to była granica zdolności, nie brak funkcji. Zamknięta
`core/f2fs.py`: superblok, checkpoint, NAT, inody, drzewa katalogów, dane
inline, katalogi inline i nieskompresowane treści.

### Czytnik

`F2fs` ma interfejs jak `Erofs` i `Ext4`: `inode()`, `listdir()`, `read()`,
`readlink()`, `walk()`, `stat()`, `resolve()`, `coverage()`. Weryfikowany
wobec `include/linux/f2fs_fs.h` **i** wobec `dump.f2fs` na obrazach
budowanych tu `mkfs.f2fs` i `sload.f2fs`: 17 pól superbloku i checkpointu
pod własnymi nazwami, 310 wpisów katalogowych wobec drzewa źródłowego, 24
inody pole po polu (288 pól), 306 treści bajt w bajt.

Siedem rzeczy czytanych jest błędnie metodą oczywistą i żadna nie zgłasza
błędu; wszystkie zmierzone na obrazie, nie przepisane:

- **NAT marnuje bajt na blok**: 455 wpisów po 9 B w 4096 B, więc indeks to
  `nid % 455`, a nie `(nid * 9) % 4096`. Blok z id węzła ping-ponguje
  między połowami obszaru NAT, a żywą połowę mówi bit bitmapy wersji NAT
  w checkpointcie.
- **Odwołania do węzłów leżą w `i_nid[]`, nie w `i_addr[]`**; `i_addr[923]`
  to dziura czytana jako pewne zero.
- **Ile bloków mieści inod** to `923 - i_extra_isize/4 - i_inline_xattr_size`,
  a ten ostatni składnik to 50 dla każdego inoda z flagą inline xattr.
  Założenie 923 przesuwa **środek** dużego pliku o 50 bloków, bez błędu.
- **Blok węzła jest inodem wtedy i tylko wtedy, gdy `footer.ino ==
  footer.nid`.** Nagłówek węzła bezpośredniego czytany jako inod daje
  wiarygodny tryb i rozmiar.
- **Bitmapa wpisów katalogowych liczy bitami od najmniej znaczącego**, a
  `f2fs_test_bit()` dla bitmap NAT i SIT — od najbardziej. Zgadzają się na
  bajku symetrycznym, więc czytnik odwrócony gubi trzeci wpis podkatalogu
  z jednym plikiem, wypisując poprawnie korzeń.
- **Zapalony bit to nie wpis**: usunięte wpisy zostawiają bity, korzeń drzewa
  skrótów trzyma w slotach `name_len = 0`. Pusty katalog zgłaszałby dwa
  pliki bez nazw.
- **`.` i `..` mają hash zero z przypadku**, nie przez haszowanie.

Hash katalogowy (TEA) jest **przeliczany i porównywany** z `hash_code`
zapisanym obok nazwy: nazwa, którą właśnie odczytaliśmy, musi dać swój
własny hash, więc zły offset, zła szerokość slotu czy złe `name_len` nie
przechodzą. 320 z 320 wpisów zgadza się na obrazie referencyjnym tego
formatu. `fs/f2fs/hash.c` był jedynym miejscem w projekcie, gdzie hash
jest wyliczany, a nie tylko czytany — po to, żeby był sprawdzalny.

### Czego czytnik nie chce, i dlaczego mówi

Zaszyfrowane wolumeny (nazwy i treści to szyfrogram, klucza nie ma w
obrazie), pliki skompresowane (F2FS trzyma blok w klastrze z nagłówkiem
długości; LZ4 i HZMA nie ma w stdlib) i pliki powyżej ok. 7,9 GiB, które
wymagają gałęzi podwójnie pośredniej — F2FS ma dwa węzły pośrednie na
inod, więc zasięg jest dwa razy większy niż w ext2. Granica podawana
liczbą, nie zgadywana. Luki w mapie bloków to nie błąd: czytają się jak
zera i są liczone.

`coverage()` rozróżnia **katalogi niewypisane** od **plików nieczytelnych**,
bo to różne straty: zaszyfrowany wolumen traci każdą nazwę i żadnych
metadanych, a raport mówiący „1 plik, 0 czytelnych" liczyłby katalog
korzeniowy i nazywał go plikiem.

### Dwa fixture pisane ręcznie i jedna granica

`mkfs.f2fs` i `sload.f2fs` dają katalogowi prawdziwy blok wpisów nawet
pustemu, a katalog z `mkdir` zamknięty od razu trzyma dwie kropki w inodzie
— i to jest kształt częsty na urządzeniu oraz jedyna gałąź, do której nic
nie dochodzi. Obszar wpisów inline, flaga kompresji i poziom szyfrowania
są zapisywane ręcznie, a asercja dotyczy **reakcji czytnika**. Granica
gałęzi podwójnie pośredniej jest sprawdzana bez pliku 9 GiB: resolver
dostaje indeks bloku ponad ostatni, jaki obsługują węzły bezpośrednie i
pośrednie, na prawdziwym inodzie prawdziwego obrazu.

### Samotest

`ext4_selftest` dostaje dwa warianty F2FS (64 MiB i 512 MiB) i 3,1 s
łącznie. Porównanie geometrii i checkpointu z `dump.f2fs -d 1` (57 pól
pod własnymi nazwami), drzewo wobec źródła, inody wobec `dump.f2fs -i`,
treści bajt w bajt, hashe nazw. Porównanie inodów jest **wyczerpujące** dla
małego wariantu i **próbką 24 z 310** dla dużego, wybieraną po kształcie
(korzeń, największy plik, największy katalog, pierwszy i ostatni wpis
największego katalogu, symlink, reszta równomiernie) — jeden proces
`dump.f2fs` na inod kosztowałby 60 ms, czyli 20 s przebiegu weryfikacji.
Obie liczby (`inodes_total`, `inodes_sampled`) są w eksporcie, żeby luka
była liczbą, a nie wrażeniem.

### Dwa moduły odpowiadały o niewłaściwym systemie plików

- `fs_check` odpalał `e2fsck -fn` na obrazie F2FS. e2fsprogs nie zna F2FS
  i mówi to swoim językiem: czyste zero i kilka linii `other` oraz
  `unreadable`, które raport zaniósłby jako ustalenia o tym urządzeniu.
  Teraz odmawia, nazywa format i podaje geometrię oraz checkpoint F2FS.
- `blockmap` używał cache z innego obrazu, bo cache leży obok *case'u*, nie
  obok obrazu. Odpowiadał „do którego pliku należą te bajty” z indeksu
  innego urządzenia: ścieżka, przesunięcie i rozmiar, z czego nic nie
  wygląda na błędne. Cache jest teraz używany tylko, jeśli zbudowano go z
  obrazu pod ręką — porównanego ścieżką **i** rozmiarem.

### Tabela formatów ma dwie kolumny

`Signature.reader` obok `Signature.readable`. `readable` znaczy „otworzy to
domyślny czytnik ext4" i decyduje, czy nieudane otwarcie dostanie zdanie z
prawdziwą nazwą formatu; `reader` mówi, który czytnik format otwiera. F2FS
i EROFS to `readable=False, reader="f2fs"`/`"erofs"`. Złączenie ich usunęłoby
to zdanie wraz z asercją, która je sprawdza, w momencie gdy F2FS dostał
czytnik.

### Czego świadomie NIE zrobiono

- **`blockmap` i `find_string` nie mają wariantu F2FS.** Pytanie „do którego
  pliku należą te bajty” wymaga odwrócenia bitmap alokacji segmentów i
  sumy SSA, a to jest droga z 7.5 krok 2 dla F2FS — inna niż dla ext4.
  Moduły odmawiają z nazwą formatu zamiast odpowiadać cudzymi liczbami,
  a samo pytanie jest zapisane w `PLAN.md` jako otwarte.
- **Sumy (`cksum`) superbloku i checkpointu nie są weryfikowane.** Tryb
  weryfikacji jest w superbloku; na obrazach z `crc = 0` nie ma czego
  sprawdzać, a uruchamianie fsck.f2fs tylko po to, żeby potwierdzić własny
  odczyt, byłoby drugim czytnikiem zamiast wyroczni.
- **`/data` z obecnego telefonu nadal nie jest sprawdzony na obrazie z
  urządzenia.** Wszystko, co tutaj, jest zmierzone na obrazach budowanych tu.

## 0.8.0 — WhatsApp: kopia zaszyfrowana rozpoznawana bez klucza, typy wiadomości

Stan bazowy: **33 checki, 526 asercji, 33/33 PASS**.

Przegląd `B16f00t/whapa` (GPL-3.0 — kod nie kopiowany, brana wiedza o
formatach; ten sam wzorzec co dla `edlclient`) pokazał dwie luki.

### Zaszyfrowane kopie WhatsApp (crypt14/crypt15)

Od 2021 kopia E2EE Whatsappa to `msgstore.db.crypt15`, a nie baza SQLite. Nasz
moduł szukał literalnie `msgstore.db` i przy pliku zaszyfrowanym oddawał
`file is not a database` — gołą wiadomość z libsqlite3, która sugeruje nieudaną
ekstrakcję, choć plik jest zdrowy i tylko zamknięty.

`appdata.whatsapp_crypt_header()` rozpoznaje obie wersje **bez klucza**:
nagłówek to `[1 bajt długości][opcjonalne 0x01][protobuf]`, gdzie pole 2 to
crypt14, pole 3 crypt15, każde z 16-bajtowym IV w podpolu. Parser protobuf
spisany od zera, wire type 2 — jedyny w projekcie.

Test jest celowo ostry: **bez 16-bajtowego IV nie ma twierdzenia „zaszyfrowane"**,
bo fałszywe twierdzenie jest gorsze niż brak odpowiedzi — wysyła analityka po
klucz, którego w obrazie nie ma, i sugeruje manipulację dowodem.

Przy okazji druga luka tego samego rodzaju: plik, który nie jest ani SQLite,
ani kopią Whatsappa, dostaje teraz konkretne zdanie zamiast surowego błędu.

### Typy wiadomości

`media_wa_type` (starsze schematy) i `message_type` (nowsze) czytane są oba, z
nazwą użytej kolumny w raporcie. Słownik typów z udokumentowanej analizy
forensicznej Whatsappa (Arenaz Benito, *Análisis forense de la aplicación
WhatsApp en sistemas Android e iOS*, Salamanca 2026) i dokumentacji
wa-crypt-tools. Kody spoza tabeli są **liczone** i opisywane jako
`niekatalogowany (N)`, nie pomijane — nieznany kod to też fakt o tym, która
wersja Whatsappa zapisała wiersz, a jego zgubienie kazałoby liczbom kłamać.

Na obrazie referencyjnym: 206 wiadomości, **169 tekst, 36 obrazów, 1 GIF**,
3 przekazane dalej, 0 oznaczonych gwiazdką. Te liczby były w bazie od początku
i nie były raportowane.

### Czego świadomie NIE zrobiono

Carving z `undark` (GPL-3.0) — **odłożone** i zapisane w `PLAN.md` 7.5 krok 3
wraz z powodem: wprowadza zależność zewnętrzną do drogi dotąd wolnej od
zależności. Jeśli kiedyś przyjęta, to jako proces wołany z zewnątrz i
raportowany z nazwą narzędzia oraz wersji, nigdy jako kod w tym repozytorium.

## 0.7.0 — TSK
 jako drugi czytnik, audyt czytnika ext4, audyt własnych parserów, manifest akwizycji

* `core/tsk.py` — warstwa dostępu do TSK: wykrywanie narzędzi, wersja, parsery
  `fsstat` / `fls` / `istat` / `ils`, odczyt `icat` do pliku tymczasowego oraz
  konwersja UUID superbloku na kolejność GUID, w której drukuje go TSK.
* Moduł `tsk_crosscheck` — sześć pytań: geometria (`fsstat`), wędrówka (`fls`),
  metadane (`istat`), **audyt extentów**, treść bajt w bajt (`icat`, SHA-256)
  oraz **pokrycie**: ile wpisów niepodlinkowanych i nieużytych inodów nasz
  reader nie pokazuje.
* TSK jest opcjonalny i nigdy nie jest wymagany — bez narzędzi moduł zgłasza
  jedno `warn`. Bez `sudo`.
* Stan bazowy: **33 checków, 526 asercji, 33/33 PASS**.

### Usunięte inody — krok 1 z 7.5

`Ext4`: `deleted_inode_count()`, `deleted_inodes()`, `free_inode_count()`,
`block_is_free()`, `inode_header()`, `recoverability()`. Moduł `deleted_files`,
check `image.deleted_files` (13 asercji).

**Wolny inod to nie usunięty plik.** Z 1 536 874 wolnych inodów obrazu
referencyjnego **784 831 nigdy nie było przydzielonych** — nazwanie ich
usuniętymi podwoiłoby liczbę i nie znaczyłoby nic. Rozdziela je `i_dtime`,
który jądro wpisuje przy unlink i zostawia zerowy w przeciwnym razie. Wynik:
**752 043 usuniętych** wobec 752 047 nieprzydzielonych wg `ils` (różnica 4)
oraz **1 536 874** wolnych wobec 1 536 876 z superbloku (różnica −2, rezerwa
journalu). Obie różnice raportowane, nie zamiecione.

**Zachowane rozmiary: 378 inodów, 6,21 MiB.** Lata usunięcia 2016-2026,
przewaga 2022 (248), pojedynczy 2026 (1).

**Treści są nieosiągalne przez inody — to wynik, nie porażka.** Sprawdzone na
próbkie 200: wszystkie mają `i_blocks = 0` i pustą mapę extentów, bo ext4 czyści
mapę bloków przy unlink. **Bajtów usuniętego pliku nie da się wskazać przez
jego inod.** Krok 2 (przestrzeń nieprzydzielona) i krok 3 (carving po nazwy)
niezrobione — moduł mówi to wprost, zamiast pokazywać listę 378 plików o
wiarygodnych rozmiarach, którą czytelnik wziąłby za listę odzyskaną.

**Nazwy nie są do odzyskania z inoda.** Niepodlinkowany wpis nie pojawia się w
żadnym katalogu; nazwa żyje tylko w bloku katalogowym, który wciąż może ją
zawierać. Każdy rekord ma pole `name_source` mówiące o tym wprost, żeby pusta
kolumna `name` nie wyglądała na brak danych.

**Wydajność.** Pierwsza wersja robiła osobne wywołanie cache na inod — 752 043
lookupy, 47 s. Czytanie tabeli inodów grupy w całości i skanowanie bajtów w
miejscu daje te same liczby w 6,2 s. Sama liczba usunięć nie buduje rekordów.

### Czytnik EROFS — domknięcie 7.4

`core/erofs.py` (nowy). Superblock, inody 32- i 64-bajtowe, drzewo katalogów i
**nieskompresowane** treści plików. Zweryfikowane podwójnie wobec definicji
formatu z `erofs_fs.h` (drzewo u-boota) i wobec `dump.erofs`: **9/9 treści
bajt w bajt**, drzewo zgodne wpis po wpisie (nazwa, nid, typ) na obrazie
nieskompresowanym i na trzech skompresowanych.

Trzy miejsca, w których czytanie „oczywiste" jest złe i nic nie zgłasza:

1. **`i_format` to trzy pola, nie numer wersji.** Bit 0 = wersja (0 → inodo
   compact 32 B, 1 → extended 64 B), bity 1-3 = układ danych. Plik może więc
   w hexdumpie wyglądać na „wersję 5" i nie być ani wersją 5, ani układem 5.
2. **W inodzie 64-bajtowym `i_nlink` jest pod 0x2C, nie 0x06**, a `i_size` jest
   **u64**. W compact 32-bajtowym `i_nlink` jest pod 0x06, a rozmiar u32. Czytanie
   złego pola daje wiarygodne zero — i właśnie dlatego `dump.erofs` zgłaszał
   „Links: 3", a my czytaliśmy 0, zanim zajrżeliśmy do definicji.
3. **Tylko ostatni, niepełny blok jest pakowany w ogień inoda.** Wszystko wcześniej
   to zwykłe bloki pod `i_u.i_blkaddr`. Czytanie `i_size` bajtów spójnie z ogona
   działa dla małego pliku i dla dużego zwraca właściwą liczbę bajtów, zmiksanych
   z inodami, które leżą dalej — plik 5000 B wyszedł jako jego owny ostatni blok
   904 B plus cokolwiek było pomiędzy. Liczba bajtów zgadzała się, treść nie.

Pakowanie wpisów katalogu: **nagłówki 12-bajtowe od początku bloku**, liczba
wpisów = `nameoff` pierwszego / 12, nazwy gdzie indywidualny `nameoff` wskazuje,
długość nazwy = `nameoff` następnego minus ten bieżący; ostatnia nazwa biegnie do
końca bloku i jest zakończona NUL-em. Moje pierwsze podejrzenie — że `nameoff` to
offset nazwy w bloku — dawało 6 „wpisów" z nieczytelnymi nazwami.

**Skompresowane dane są odrzucane, z powodem.** LZ4 nie ma w stdlib, a warstwa
analizy ma zero zależności. `/system` na skompresowanym obrazie daje poprawne
drzewo nazw, rozmiarów, trybów i czasów — i żadnej treści pliku. `coverage()`
mówi to wprost, a `image_info` raportuje to jako `warn`, nie jako sukces.
Czytnik, który wylicza katalogi, ale nie czyta plików, **wygląda jak działający** —
to ta sama klasa błędu co cicha pustka z tury 8, więc zakres jest jawny.

Samotest w `ext4_selftest` buduje dwa obrazy (`mkfs.erofs`, bez kompresji i
`-zlz4`) i porównuje z `dump.erofs` drzewo (nazwa, nid, typ) i treści bajt w bajt.
Skompresowany build jest w samoteście **celowo**, żeby ścieżka odmowy była
sprawdzona na prawdziwym skompresowanym inodzie, a nie na ręcznie zrobionym.
Bez `erofs-utils` samotest mówi to wprost i nie raportuje niczego — samotest, który
pomija po cichu, to samotest, który przestał działać.

### Rozpoznawanie formatów — ściana zdolności zamiast ściany ciszy

`core/fsformat.py`. Dotąd brak magiki ext4 znaczył „to nie jest czytelny obraz
ext2/3/4" — zdanie prawdziwe i bezużyteczne, bo analityk trzyma w ręku
partycję EROFS, czyli format każdego Androida 10 i nowszych, i dowiadywał się
tyle, że coś jest nie tak. Teraz wiadomo, co.

| format | magic | offset |
|---|---|---|
| ext2/3/4 | `0xEF53` | 1080 |
| EROFS | `0xE0F5E1E2` | 1024 |
| F2FS | `0xF2F52010` | 1024 |
| squashfs | `0x73717368` | 0 |

Offsety **zmierzone** na obrazach zbudowanych w tej sesji (`mkfs.erofs`,
`mkfs.f2fs`, `mksquashfs`), nie przepisane z tabel. Liczy się to: trzy z czterech
formatów trzymają magikę 1024 bajty w, za nagłówkiem partycji, a squashfs na
samym początku — czytnik patrzący tylko w offset 0 nie znalazłby żadnego.
W `mke2fs` i `mkfs.erofs` utknęłam na chwilę na błędnym `-T ts`; przypadek
pokazuje, po co mierzyć zamiast pamiętać.

`image_info` przy odmowie podaje format, jego obsługę i co to oznacza dla
sprawy. `Ext4` dopina nazwę formatu do komunikatu o złej magice — ale **tylko
gdy format jest rozpoznany**; przy faktycznie uszkodzonym ext4 podpowiedź
milczy, bo pewna zła diagnoza jest gorsza niż zwykły komunikat.

**Sam czytnik EROFS nie powstał w tej turze.** Superblock, inode (64 B i 32 B
compact) i dane inline udało się odczytać i potwierdzić `dump.erofs`; pakowanie
wpisów katalogu okazało się osobnym problemem, a dekompresja LZ4 jest
niemożliwa przy stdlib. Czytnik, który czyta metadane i nie potrafi odczytać
pliku, wygląda jak działający — to ta sama klasa błędu co cicha pustka z tury 8,
więc nie został napisany. Kolejne tury: 7.4 w całości, zaczynając od katalogów.

Samotest formatów w `ext4_selftest` używa **ręcznie umieszczonych magików**, nie
czterech dodatkowych pakietów: samotest potrzebujący `mkfs.erofs`, `mkfs.f2fs`
i `mksquashfs` to samotest, który po cichu przestanie działać. Asercje pilnują
też, że komunikat odmowy **wymienia format** — to cały sens tabeli.

### Eksport body file (`mactime_export`) i czwarty błąd w `ext4`

**Eksport.** `core/timeline.py` dostaje `body_line()`, `body_file()`,
`mactime_mode()`. Moduł `mactime_export` zapisuje `mactime.body` i
`mactime.csv`, **waliduje plik przez `mactime -i day -d`** i porównuje inwentaryz
z `fls -r -m` jako ujawnienie, nie sprawdzenie. Format ustalony metodą błędu,
nie opisu — podanie kandydatów `mactime` i przeczytanie jego pretensji dało
trzy rzeczy, których nie zgadłem: **nazwa jest drugim polem, nie ostatnim**;
czasy to **sekundy od epoki** („isn't numeric in numeric lt" dla daty);
pole trybu to `typ/` + **typ + uprawnienia**, a dla gniazda powtórzona litera to
`h`, nie `s`. Kolumna MD5 = `0` — nie liczymy MD5, bo narzędzie haszuje SHA-256,
a zero jako „nie liczono" jest jaśniejsze niż pominięcie pola.

Walidacja przechodzi: 150 566 wpisów, 1 416 dni w indeksie. **102 pliki nie da
się zapisać** — nazwa zawiera znak końca wiersza, wszystkie z pakietu
`pl.k2.droidoaudioteka`. Format body nie ma na to sposobu, więc są pomijane —
ale **raportowane**; pierwsza wersja modułu gubiła je bezgłośnie. Wirtualny
`$OrphanFiles` wyłączony z porównania, bo TSK liczy go jako żywy plik, choć nie
ma go na dysku. Po wyłączeniu: **TSK 150 668 żywych, my 150 668 — co do liczby.**

**Czwarty błąd w `core/ext4.py`, znaleziony właśnie przez ten eksport**, bo
`fls -m` ujawnia wszystkie cztery czasy każdego pliku, a `tsk_crosscheck`
porównywał osiem. Dwa błędy, oba ciche:

1. **Pola epoki leżą pod STAŁYMI offsetami** 0x84 / 0x88 / 0x8C, a nie pod
   `0x84 + extra_isize` — czytanie wyprzedzało je o 28 bajtów, na sumę
   kontrolną inoda. `atime` pliku `/dpm/fdMgr/fd.conf` wyszło **7596558217525865027**.
2. **Rozszerzenie wolno zastosować tylko gdy low 32-bitowy ≥ 0x80000000.** Jądro
   utrzymuje te pola tylko po przepełnieniu 2038. Ten obraz ma **40 000 inodów**
   z wartościami w wiarygodnym zakresie właśnie tam, więc bezwarunkowe
   OR-owanie zamieniało czasy z 2016 na daty rzędu 200 milionów — i **wyjmowało
   pliki poza cutoff `fs_timeline`, czyli znikały z osi czasu**.

Potwierdzenie: porównanie z `fls -r -m` **wszystkich 150 668 inodów** —
rozmiar, uid, gid, atime, mtime, ctime, crtime: **zero różnic**. Pozostałe
3 329 różnic trybu i 12 109 różnic nazwy są w 100% wpisami usuniętymi.

Check `timeline.mactime` (13 asercji). **Weryfikacja: 32/32 PASS, 474 asercje.**

### Atrybuty rozszerzone (xattr) — `security.selinux` i nie tylko

`core/ext4.py` czyta teraz blok atrybutów rozszerzonych za `i_file_acl`.
Układ **zmierzony** na trzech prawdziwych blokach obrazu referencyjnego, nie
przepisany z dokumentacji. `Inode` dostaje `xattrs`, `xattr_text()` i `selinux`,
`Ext4.read_xattr(path, name)`, a `stat()` ma pola `xattrs` i `selinux`.

**Trzy bramki walidacji, każda rzuca `Ext4Error`:** wskaźnik poza wolumenem,
magic ≠ `0xEA020000`, `e_name_index` nieprzypisany do prefiksu — plus wartość
wskazująca poza blok i niemożliwa liczba wpisów. Wskaźnik **0 nie jest błędem**,
to stan normalny: na obrazie referencyjnym dotyczy 1 687 549 z 1 687 552 inodów.
Sprawdzone na czterech przypadkach. `e_hash` **nie jest liczony** i tak jest to
wprost powiedziane.

**Fixture zbudowany ręcznie, bo `debugfs ea_set` go nie tworzy.** Moduł
`ext4_selftest` składa blok 88 B na wolumenie `desc32` (`^64bit,^metadata_csum` —
bez `metadata_csum` jądro nic nie przelicza, więc test sprawdza parser, a nie
sumę), wpisuje go do obrazu i ustawia `i_file_acl`. Czytnik zwraca wartość
**co do bajtu**, a `debugfs` niezależnie potwierdza numer bloku. Dwa błędy w
budowie, oba ciche:

- nazwa w polu `e_name` to **sufiks** po prefiksie, nie pełna nazwa —
  `security.selinux` w tym polu daje atrybut `security.securit`, bez błędu
- padding liczony w jednym wyrażeniu, gdzie `len(entry)` to jeszcze tylko część
  stała: blok miał **osiem bajtów za dużo** i wartość czytała się przesunięta

**Census w `image_info`**: przechodzi 1 687 552 inodów i raportuje różne
etykiety SELinux. Wynik na obrazie referencyjnym: 3 inody z blokiem atrybutów,
nazwa `security.restorecon_last` ×3, **0 etykiet SELinux** — i finding mówi
wprost dlaczego: etykiety plików `/system` pochodzą z kontekstu montowania i
polityki, nie z zapisanych atrybutów. Bez tego zdania czytelnik mógłby dojść do
wniosku, że etykiet w ogóle nie ma.

### Syntetyczne obrazy ext4 w regresji (`ext4_selftest`)

Do tej pory cała siatka bezpieczeństwa opierała się na jednym obrazie z jednego
telefonu. TSK dał niezależność **implementacji**, nie **danych**. Moduł buduje
wolumeny poleceniem `mke2fs` i sprawdza na nich czytnika — **9 wariantów,
0,6 s, bez root i bez montowania**, w `work/_synthetic/ext4/`.

Trzy wyniki, każdy mówi coś, czego nie wiedziałem przed testem:

- **Bucket `silent` to właściwy test.** Każdy wariant ląduje w jednym z trzech
  koszy: przyjęty, odrzucony albo **cichy** (otwarty bez błędu, pustka w
  zwrocie). `silent` jest `critical`, nigdy passem — to dokładnie ta cicha
  awaria, którą odrzucenia z tury 8 miały zlikwidować.
- **Odmowa bywa leniwa.** Wyjątek trzeba łapać wokół **całej wędrówki**, nie
  tylko konstruktora: `meta_bg` odmawia przy otwarciu, mapowanie ext2 dopiero
  przy pierwszym czytaniu inoda korzeniowego.
- **Moje oczekiwanie dla `inline_data` było błędne, nie czytnik.** Zakładałem
  odmowę; test ją wykluczył — `mke2fs` ustawia flagę, ale świeży obraz ma
  **0 plików regularnych**, więc nie ma czego nie umieć. Oczekiwanie poprawione,
  a w wariancie zapisane `does_not_prove`: odmowa dla prawdziwego pliku inline
  pozostaje nietestowana, bo mke2fs takiego pliku nie tworzy, a debugfs nie ma
  do tego polecenia.

Wariant `desc32` (`-O ^64bit,^metadata_csum`) okazał się najważniejszy: bez
niego wszystkie warianty miały `desc_size=64`, bo takie są domyślne ustawienia
współczesnego mke2fs. On jako jedyny odróżnia drogę 32-bitową — tę samą, którą
w obrazie referencyjnym.

Cross-check nazw cech z `dumpe2fs` (`64bit`, `metadata_csum`, `inline_data`,
`meta_bg`) zgadza się we wszystkich przypadkach. Sama geometria by tego nie
wyłapała — to porównanie z `dumpe2fs`, a nie liczby, znalazło błędne tabele bitów
w turze 8.

**Fixture xattr: nieudany i udokumentowany.** `debugfs -w -R "ea_set ..."`
zgłasza sukces, `ea_list` drukuje atrybut, ale `i_file_acl` zostaje 0,
`debugfs stat` to potwierdza, a `i_block` trzyma magic extentów. To **drugi raz**
`ea_list` mówi coś, czego `i_file_acl` nie potwierdza — tym razem na obrazie,
który sami zbudowaliśmy, więc wątpliwość rozstrzygnięta. Moduł raportuje to
jako `info` z powodem. **Korekta K5 z planu**: fixture dla czytnika xattr
trzeba budować ręcznie, na wolumenie bez `metadata_csum`, żeby nie liczyć sumy.

### Manifest akwizycji: `acquisition.json` + `hashes.csv`

Przegląd `androidqf` (akwizycja logiczna po ADB) pokazał, że nasza akwizycja ma
plan, ale nie ma rejestru ukończenia w formie, którą da się czytać bez znajomości
narzędzia. Dodane:

- `acquisition_status()` — czysta funkcja klasyfikująca akwizycję
  (`planned` / `completed` / `partial` / `failed`) z trzech faktów: czy wykonano,
  kod wyjścia, rozmiar wobec planu. **9/9 przypadków poprawnych, testowalne bez
  telefonu** — bo to ta funkcja decyduje, czy raport może twierdzić, że ma całą
  partycję. Kluczowy przypadek: `rc != 0` przy pliku pełnego rozmiaru daje
  `partial`, nie `completed`; sam rozmiar tego nie wyłapie.
- `hashes.csv` — `name,source,sha256,bytes,recorded_utc`, bez wiersza o sobie.
  Pole `source` od razu, bo planowana odzyskiwanie plików usuniętych użyje
  `blkls` z TSK jako drugiego wejścia akwizycji do tego samego katalogu.
- `acquisition.json` — producent, UUID, czasy, status, zadania, kontekst. Nazwa
  celowo pokrywa się z androidqf, więc pole `producer` mówi, kto wygenerował
  plik, gdyby oba trafiły do jednego katalogu.
- `size_matches_plan` zawsze `true` / `false` / `null`, nigdy nieobecne.
- `report._acquisition`: `acquisition.json` to źródło prawdy dla stanu,
  `edl_<label>.json` zostaje szczegółem planu. Raport **nazywa oba manifesty**
  (`acquire/hashes.csv` = akwizytowane, `exports/extract_manifest.json` =
  wyekstrahowane do analizy) i mówi wprost, żeby nie zliczyć pliku podwójnie.
  Stan `partial` daje osobny werdykt.

Wymaganie licencyjne z przeglądu androidqf spełnione: MVT License 1.1 =
MPL-2.0 **+ klauzula 3.0 „Consensual Use Restriction"** — kod nie kopiowany,
wzorzec jak dla `edlclient` (projekt, nie kod).

Dwa błędy znalezione przy okazji:
- `report.source()` cache'uje **po nazwie modułu**, więc drugi plik tego samego
  modułu był nieczytelny, a `edl_acquire` zapisuje teraz trzy. Dodane
  `read_export()` bez cache'a.
- `run_job` wychodził z `dry_run` **przed** ustawieniem `status` — ścieżka
  domyślna nie miała statusu wcale, a to najczęstszy przypadek i ten, który
  najbardziej potrzebuje czytelnego „mamy plan, nie mamy danych".

### Audyt własnych parserów (odpowiedź na pytanie „czy TSK da drugie zdanie")

**TSK: nie.** Wszystkie 33 narzędzia to warstwa bloków / systemu plików /
metadanych; jedyny parser formatu to `jpeg_extract`. Żadnego SQLite, Chromium
ani aplikacji. Pytanie o `sqlite`/`chromium`/`appdata` ma odpowiedź: nie na
warstwie pliku.

**Tak, ale od innych narzędzi — i to dotyczy kodu, który napisaliśmy sami.**
Większość tego narzędzia czyta bazy przez `sqlite3`, czyli implementację
referencyjną, więc jej autorytet dostaje za darmo. Dwa miejsca są inne, bo to
reimplementacje:

* `sqlite_tools.leaf_rows` — własny dekoder formatu rekordów SQLite
* `appdata.classify` — rozpoznanie formatu z czterech magii i testu pierwszego
  bajka

* `sqlite_tools.walk_table()` (nowy) — spacer b-drzewa z indeksem
  rowid → pozycja, `overflow_at` i `ascending`. Umożliwia porównanie z
  `sqlite3` wiersz po wierszu zamiast porównywania zbiorów.
* `appdata.magic_verdict()` / `classify_checked()` — drugie zdanie z libmagic
  (`file -b -` na stdin, bez pliku tymczasowego). Gdy nasz klasyfikator mówi
  `opaque`, a libmagic rozpoznaje format, raportujemy to, co powiedział
  libmagic, i zapisujemy jego dosłowną etykietę jako dowód. Klasa `text` —
  plik `ACRA-INSTALLATION-…` jest dla nas `opaque`, a dla libmagic „ASCII text",
  czyli identyfikator, którego nie chcieliśmy przeoczyć.
* Moduł `decoder_audit` + check `report.decoder_audit` (25 asercji).
* `chromium`: `HEURISTIC`, `SECRET_VERDICT_BASIS`, `XS_BASIS` — jawne
  oznaczenie, że identyfikatory z URL-i i werdykty o szyfrowaniu są
  **heurystykami**, nie ustaleniami. Każdy taki finding niesie `heuristic: true`
  i podstawę; `chrome_history`, `login_data` i `cookies_webview` cytują ją
  w detail.

### Wynik audytu na obrazie referencyjnym

| baza | tabele | rekordy | wartości | uwagi |
|---|---|---|---|---|
| `contacts2.db` | 43/43 (1 pominięta) | 26 317 = 26 317 | 560/600 | 16 wierszy z overflow, 40 starszych niż schemat |
| `accounts.db` | 7/7 | 433 = 433 | 49/49 | — |

Cztery rzeczy, które wyglądały na błędy, a okazały się cechami danych — każda
z nich najpierw zgłosiła się jako awaria:

1. **Alias `INTEGER PRIMARY KEY`.** Kolumna `_id` leży w rekordzie jako `NULL`,
   a wartość podstawia `sqlite3` z rowid. `accounts` raportował 1 z 49 wartości
   zgodnych; przyczyną były trzy `None`, które powinny być rowidami. Sam dekoder
   był poprawny.
2. **Kolejność bez `order by`.** `select rowid from extras` bez `ORDER BY`
   odpowiada z indeksu: `7, 171, 209, 259…` przy b-drzewie `1, 2, 3, 4…`. Zbiory
   równe, kolejności nie. Moja kontrola testowała plan zapytania, nie dane, i
   zgłaszała 9 zaburzeń w doskonałym dekodze. Teraz `order by rowid`.
3. **`ALTER TABLE ADD COLUMN`.** `calls` ma 51 kolumn, najstarsze rekordy 50.
   `sqlite3` dopełnia wartością domyślną ze schematu, na dysku jej nie ma. To
   osobna klasa `schema_evolved`, raportowana jako informacja, nie błąd.
4. **Wskaźniki komórek to offsety w bajtach, nie numery stron.** Numer strony
   dziecka siedzi w pierwszych 4 bajtach komórki. Pomylenie daje numery
   większe niż plik, które wyglądają jak uszkodzenie, a nie jak błąd w czytniku.

Efekt uboczny wart odnotowania: największym ryzykiem nie było SQLite (tam
`sqlite3` jest naszym odwołaniem), tylko `chromium.py` — `url_identity_hints` to
siedem wyrażeń regularnych, `classify_secret` to test prefiksu, a
`decode_facebook_xs` to założenie o układzie pól. **Nie ma implementacji
referencyjnej**, więc drugiego zdania nie ma. Najsilniejsze potwierdzenie
wewnętrzne: identyfikator konta z ciasteczka `c_user` (FB Lite) pojawia się
niezależnie w 3 innych plikach — bazie ciasteczek i dwóch `.ldb` z Local Storage.

### Trzy błędy w `core/ext4.py`, znalezione przez porównanie z dumpe2fs

Każdy z nich został potwierdzony niezależnym narzędziem, nie zgadywany.

1. **`free_blocks` było 3448× za duże.** 8 592 424 472 zamiast 2 494 472, różnica
   dokładnie 2 × 2³². Górna połowa `s_free_blocks_count_hi` jest pod `0x158`, nie
   `0x160`; `0x160` to `s_flags`, a na tym wolumenie ma wartość 2
   (`EXT2_FLAGS_UNSIGNED_HASH`). Dodatkowo górne połowy liczą się tylko przy
   fladze 64BIT.
2. **`journal_inum` czytane z `0xE8`, czyli z `s_last_orphan`.** Raport podawał
   `journal_inode: 229666`; `dumpe2fs` i `fsstat` mówią 8. Pole `last_orphan`
   jest teraz czytane i raportowane osobno.
3. **Tabele bitów cech były przesunięte.** `has_journal` było pod `0x0004`
   zamiast `EXT_ATTR`, `uninit_bg` nie było w ogóle, `METADATA_CSUM` siedziało
   pod `0x4000` zamiast `0x0400`. Na obrazie referencyjnym 6 z 9 nazw w raporcie
   było złych (`HASH_DIR` zamiast `RESIZE_INODE`, `DIR_NLINK` zamiast
   `UNINIT_BG`, `HAS_JOURNAL` zamiast `EXT_ATTR`).

   Mapowanie **zmierzone**, nie odtworzone z pamięci: `mke2fs -O ^cecha` na
   czystym obrazie i porównanie superbloku przed i po, plus `dumpe2fs` jako
   rozstrzygacz. Zmierzone: `has_journal` 0x4, `ext_attr` 0x8, `resize_inode`
   0x10, `dir_index` 0x20 (compat); `filetype` 0x2, `extent` 0x40, `64bit` 0x80,
   `flex_bg` 0x200, `metadata_csum_seed` 0x2000 (incompat); `large_file` 0x2,
   `huge_file` 0x8, `uninit_bg` 0x10, `dir_nlink` 0x20, `extra_isize` 0x40,
   `metadata_csum` 0x400 (ro_compat). Wynik zgadza się z `dumpe2fs` co do nazwy.

### Odmowa zamiast cichego braku danych

`_parse_extents` zwracało `[]`, gdy `i_block` nie zaczynał się magią `0xF30A`.
Na wolumenie ext2 to oznaczało, że `listdir` zwraca pustkę, `read` zwraca
`b""`, a całe poddrzewo znika z raportu bez żadnego błędu — nieodróżnialne od
„nic tam nie było". Teraz `Ext4Error` z podaniem numeru inoda i powodu.

Uwaga: `EXT4_EXTENTS_FL` (0x8000) **nie** jest testem na dysku. To flaga, którą
kernel OR-uje do `i_block[0]` w pamięci; na dysku zawsze leży `0xF30A`.
Sprawdzanie 0x8000 odrzucałoby każdy inode z extentami, łącznie z korzeniem.

`metadata_bg` odrzucane tylko gdy `s_first_meta_bg > 0`. Sam fakt flagi nie jest
powodem: na zmierzonym obrazie `meta_bg` z `s_first_meta_bg = 0` mke2fs układa
tablicę deskryptorów ciągle i nasz reader czyta ją poprawnie — 7/7 ścieżek i 7/7
treści identycznych z TSK. Odmowa byłaby odmową czytnika, który działa.

### Audyt extentów: nowy check `extents`

`i_blocks` to jedyne niezależne liczbowe odwołanie do tego, czy drzewo extentów
zostało przeczytane w całości. Porównanie musi uwzględniać **bloki drzewa**, nie
tylko bloki danych — `i_blocks` liczy jedne i drugie. Pierwsza wersja checku
porównywała same bloki danych i zgłosiła fałszywą rozbieżność na 1,4% plików,
które były w porządku.

`Inode` ma teraz `extent_tree_blocks`, `data_block_count` i `total_block_count`.
Na próbce 8000 plików z obrazu referencyjnego inwariant
`data + tree == i_blocks / (block_size / 512)` zachodzi **100,00%**.

Katalog główny (inode 2) jest wyjątkiem: kernel rezerwuje mu dodatkowy blok na
samoreferencyjne `..`, więc jego `i_blocks` jest o jeden większe niż opisuje
drzewo extentów. Znany wyjątek, nie finding — check, który krzyczy na inode 2,
zostanie zignorowany.

### Rzeczy odczytane z TSK, których nie zgadywaliśmy

* UUID wolumenu: te same bajty, `57f8f4bc…` u nas, `5bf2f9c0…` w `fsstat`.
* Zakresy w `fsstat` to granica, nie liczba (`Inode Range: 1 - 1687553` przy
  `s_inodes_count` = 1 687 552), więc liczby porównujemy sumując zakresy grup.
* `fls` ma **dwa** znaczniki przydziału: `/` na pozycji 1 to stan bitmapy
  inoda, a `*` po literze typu oznacza **niepodlinkowany wpis katalogowy**.
  Na tym obrazie wszystkie 202 592 inody są przydzielone, a 51 924 nazwy
  niepodlinkowane — parser czytający pierwsze `*` zgłosiłby pusty system plików.
* `fls` drukuje też wirtualny pojemnik `$OrphanFiles`, którego nie ma na dysku —
  nie wolno go liczyć jako wpisu.
* Litera typu z inoda (`r` dla pliku zwykłego) stoi w `fls` na pozycji 3;
  litery `V` i `-` też się zdarzają.
* Nagłówek `ils` ma 11 kolumn — `st_size` to indeks 10, nie 9.
* Wyjście `fls` nie jest UTF-8: nazwy pomocniczych tabel FTS (MicroMsg/WeChat)
  to bajty surowe, więc `surrogateescape`, nie `replace`.
* `istat` nazywa bloki danych inoda z extentami „Direct Blocks", a bloki drzewa
  osobno — „Extent Blocks".


## 0.5.0 (dodatki po turze 5) — tura 7: audyt polityki sekretów

* `core/secrets.py` — rejestr odcisków (SHA-256) wszystkich opakowanych sekretów,
  wzorce kształtu tokenów i kluczy, kontrola pól JSON i komórek CSV.
* Moduł `secret_audit` — rozróżnia trzy klasy artefaktów: pochodne (muszą być
  czyste), dowody z obrazu (bajt w bajt, wyłączone jawnie) i stan roboczy
  (niezamaskowany celowo, wymagany tryb 0600).
* Check `report.secret_audit` (20 asercji) z asercją `known_secrets >= 8`, żeby
  pusty rejestr nie mógł przejść jako sukces.
* Wykryte i naprawione 4 wycieki, których nie zauważyła ręczna poprawka z tur 4/5:
  hasła w `accounts_db`, tokeny „bez pary" w `authtoken_journal`, `password.key`
  w `pin_recovery`.

## 0.5.0 (dodatki po turze 5) — tura 6: sesja od strony systemu

* `core/sysstate.py` — parsery stanu systemu poza `/data`: historia awarii
  (`klo`), rejestry restartu jądra, migawki procesów z różnicami, logi MIUI,
  obecność statystyk baterii.
* Moduł `session_system` — 29 zapisów poza `/data` w sesji 2026, sklasyfikowanych
  i przeanalizowanych plik po pliku; sekcja w raporcie.
* Poprawka `net_state` — liczniki ruchu są w `/system/netstats`, nie tylko
  `/data/misc/netstats`; werdykt przemianowany na „sesja uwierzytelniona" i
  oparty wyłącznie na sygnale z datą.

## 0.5.0 — tura 5: raport, `verify --scope full`, `newcase`, packaging

* `core/reporting.py` — raport jako **dokument**: obraz, werdykty, tabela
  kont (uwierzytelnienie vs aktywność), znalezione sekrety, sesja, wiarygodność
  dat, **źródła** (plik + czas zapisu) i lista brakujących eksportów.
* `report` przebudowany: czyta `work/<case>/exports`, więc dokument można
  złożyć po wielu sesjach; nowy parametr `reveal` odsłania sekrety tylko
  na wyraźne życzenie.
* `verify --scope full` — dokłada `cases/<case>.local.json` (poza gitem) do
  case'u publicznego; rozdzielenie chroni wartości sekretów przed commitem.
* `newcase` — generator case'a: zapisuje to, czego nie da się wymyślić
  (geometria, UUID, opcjonalnie SHA-256) i zostawia checki z wartościami
  `TODO`, żeby pierwszy `verify` wypomniał, czego brakuje.
* `core/fsscan.py` + `Ctx.file_scan()` — **jeden** przebieg obrazu
  (150 668 wpisów) obsługuje `fs_timeline`, `unlock_proof` i `clock_anomaly`:
  regresja `verify --scope all` spadła z ~40 s do ~21 s.
* `ext4.stat()` zwraca też `*_unix`/`*_utc`; `ext4.inode()` przyjmuje
  `DirEntry`.
* Packaging: entry point `forensic`, wersja 0.5.0, ten CHANGELOG.

## 0.4.0 — tura 4: oś czasu, sesja, sieć, WiFi, zegar

* `core/timeline.py` — `Event`, `epoch_seconds` (s/ms/µs po skali oraz ISO),
  `dedupe`, `group_runs`, `last_per_source`, strefa Europe/Warsaw bez tzdata.
* Moduły: `fs_timeline`, `login_timeline`, `unlock_proof`, `net_state`,
  `wifi_creds`, `clock_anomaly`.
* Naprawa polityki sekretów: `Masker` maskuje tylko obiekty `Secret`, więc
  eksporty tur 2–3 zapisywały tokeny, hasła i PIN jawnym tekstem; sekrety są
  teraz opakowywane u źródła. Wartość PIN-u i soli usunięta z case'a (plik jest
  w gicie).
* `curses`: `color_pair()` wołane z dwoma argumentami wywracało każdą
  nawigację na menu — poprawione.

## 0.3.0 — tura 3: aplikacje i akwizycja

* `core/appdata.py` — wspólne parsery: `shared_prefs`, strumienie Java,
  `PropertiesStore_v02`, tokeny `EAA` (z oddzieleniem szumu base64), `threads_db2`,
  `prefs_db`, `msys`, `msgstore`, `axolotl`, `localappstate`,
  `package-usage.list`, `backup_record.xml`, `components-history.json`.
* `acquisition/edl_job.py` — plan odczytu dla zewnętrznego `edlclient`:
  geometria z `rawprogram0.xml`, budowa argv, brak czasownika zapisu,
  `dry_run` domyślnie.
* Moduły: `messenger`, `fb_tokens`, `whatsapp`, `snapchat`,
  `app_install_timeline`, `edl_acquire`.

## 0.2.0 — tura 2: konta i kredensjale

* `core/sqlite_journal.py` — rollback journal z wyzerowanym nagłówkiem.
* `core/chromium.py` — `Login Data`, `Cookies`, `History` z rozpoznawaniem
  schematów po `pragma table_info`.
* `core/aosp.py` — `locksettings.db`, `Long.toHexString`, format
  `password.key`, przeszukanie PIN-u.
* Moduły: `accounts_db`, `authtoken_journal`, `login_data`, `cookies_webview`,
  `chrome_history`, `pin_recovery`.

## 0.1.0 — tura 1: obraz i system plików

* `core/ext4.py` — read-only ext2/3/4 (superblock, grupy, inode, extenty,
  katalogi) oraz `core/blockmap.py` — indeks bloków „offset obrazu → plik”.
* Moduły: `image_info`, `mount_ro`, `fs_check`, `blockmap`, `find_string`,
  `extract_file`, `sqlite_info`, `verify`, `report`.
* Dwa frontendy (numerowane menu, `curses`) na jednym kontrolerze, i18n PL/EN,
  maskowanie sekretów, `preflight`.
