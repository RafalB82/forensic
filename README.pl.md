# forensic

Narzędzie forensic do obrazów partycji Android. Czyta wolumeny ext4, F2FS i
EROFS wprost, bez montowania, i odpowiada na pytania, które analityk zadaje
wyrzuconemu urządzeniu: czyje konta na nim były, kiedy ostatnio odblokowano, co
usunięto przed zatrzymaniem i co jeszcze da się odzyskać.

* **Offline.** Zero wywołań sieciowych, zero telemetrii, żadnej usługi
  zewnętrznej. Działa na stacji roboczej bez łącza.
* **Tylko do odczytu.** Obraz nigdy nie jest modyfikowany. Każdy artefakt trafia
  do osobnego katalogu roboczego.
* **Dwa języki.** Polski i angielski w całym interfejsie, przełączane w trakcie
  pracy.
* **Sekrety maskowane** domyślnie, odsłaniane tylko na żądanie.

## Spis treści

- [Co narzędzie daje](#co-narzędzie-daje)
- [Wymagania](#wymagania)
- [Instalacja](#instalacja)
- [Uruchomienie](#uruchomienie)
- [Konfiguracja](#konfiguracja)
- [Moduły](#moduły)
- [Typowa sesja](#typowa-sesja)
- [Case i weryfikacja](#case-i-weryfikacja)
- [Testy](#testy)
- [Gdzie są wyniki](#gdzie-są-wyniki)
- [Formaty i granice](#formaty-i-granice)
- [Akwizycja](#akwizycja)
- [Licencja](#licencja)

## Co narzędzie daje

**Wizję urządzenia, która przetrwała zatrzymanie.** Konta wraz z ostatnim
uwierzytelnieniem i ostatnią aktywnością, zapisane logowania w przeglądarce,
ciasteczka, historia przeglądania i wyszukiwania, sieci WiFi z kluczami, stan
blokady PIN-u, dowód odblokowania oraz stan sieci w chwili zrzutu.

**Dane aplikacji tak, jak aplikacje je faktycznie zapisują.** Messenger, WhatsApp,
Facebook, Snapchat: która baza wciąż trzyma tekst rozmów, które tokeny i klucze
istnieją oraz gdzie aplikacja nie zostawiła po sobie nic. Raport mówi, który
z tych przypadków zachodzi, zamiast wypisywać pustą tabelę.

**Oś czasu ostatniej sesji.** Każdy plik zapisany po wybranym momencie, pogrupowany
w serie, plus strona systemowa tej samej sesji — zrzuty awarii, rejestry restartu
jądra, migawki procesów, liczniki ruchu. Werdykt, którym znacznikiem czasu można
ufać, bo zegarek urządzenia kłamie.

**Usunięte dane w zakresie, w jakim wciąż istnieją.** Inody po usunięciu wpisów,
z zadeklarowanym rozmiarem; nazwy usuniętych plików odzyskane z bloków
katalogowych; inwentaryzacja przestrzeni nieprzydzielonej oraz kandydaci na
treść wydobyci z niej — każdy z oceną, jak daleko dało się go zweryfikować.

**Raport mówiący, skąd wzięła się każda liczba.** Obraz i jego geometria, werdykty
wraz z dowodami, tabela kont rozdzielająca ostatnie uwierzytelnienie od ostatniej
aktywności, znalezione sekrety (maskowane), ostatnia sesja, wiarygodność dat oraz
źródła wraz z czasem ich zapisania — razem z tymi, których brakuje.

**Eksport w formacie, który inne narzędzia przyjmują.** Cały system plików jako
body file, czyli inwentarz w formacie czytanej przez każde narzędzie osi czasu w
tej branży, więc wyniki wchodzą wprost do `mactime`, arkusza albo innego
narzędzia case'owego.

**Odpowiedź na pytanie „który plik jest pod tym offsetem".** Pytanie odwrotne, w
obu kierunkach: offset w obrazie na plik i pozycję w nim, i plik na offsety w
obrazie. Wokół tego pytania zbudowane jest całe narzędzie, bo montowanie obrazu
tej odpowiedzi nie daje.

## Wymagania

* Linux, Python 3.10 lub nowszy. Żadnych zewnętrznych pakietów Pythona.
* Python 3.10+ oznacza expat 2.4.1 lub nowszy, a to jest powód, dla którego
  parsowanie XML-a z obrazu jest bezpieczne: expat nie rozwija encji zewnętrznych
  ani rekurencyjnie zdefiniowanych, a wersje podatne na „billion laughs” są
  starsze niż wymagane minimum. Ponadto każde parsowanie XML-a powyżej 5 MiB jest
  odrzucane (`forensic/core/xmlsafe.py`), więc praca, jaką może wywołać
  przesadnie duży plik preferencji, jest ograniczona.
* Opcjonalne, używane gdy są, pomijane z ostrzeżeniem gdy nie ma: `e2fsprogs`
  (`e2fsck`, `dumpe2fs`, `debugfs`, a także `mke2fs` na potrzeby samotestu),
  The Sleuth Kit
  (`apt install sleuthkit`, niezależna weryfikacja krzyżowa), `sqlite3`, `file`,
  `xxd`.
* Opcjonalne: zewnętrzny toolchain EDL, wyłącznie do akwizycji. Nie jest częścią
  tego projektu i nie jest potrzebny do żadnej analizy.

Sprawdzenie, co jest dostępne:

```bash
./forensic.py --preflight
```

Raportuje interpreter, narzędzia opcjonalne, zależność EDL, sudo, USB i wolne
miejsce na dysku oraz skonfigurowany case i obraz. Gdy obraz nie jest
skonfigurowany, mówi to wprost — `nie skonfigurowano obrazu (użyj --image)` —
zamiast zgłaszać brak pliku, którego nikt nie podał.

## Instalacja

```bash
./install.sh                 # venv + sam pakiet
./install.sh --no-venv       # instalacja w bieżącym interpreterze
```

Albo sam pakiet:

```bash
pip install .
forensic --version
```

W obu przypadkach dostajesz polecenie `forensic`; repozytorium ma też
`./forensic.py`, które działa bez instalowania czegokolwiek i jest używane
w przykładach poniżej.

## Uruchomienie

```bash
./forensic.py                      # menu, albo curses TUI na terminalu, który da radę
./forensic.py --ui menu            # wymuś menu tekstowe
./forensic.py --ui curses          # wymuś pełnoekranowy TUI (wraca do menu, gdy się nie da)
./forensic.py --list               # lista wszystkich modułów
./forensic.py --preflight          # sprawdzenie środowiska
./forensic.py --cli <moduł>        # uruchom jeden moduł i wyjdź
./forensic.py --lang en            # interfejs angielski
./forensic.py --reveal             # sekrety w jawnej postaci
```

Oba frontendy mają ten sam kształt. Kategorie to cyfry, akcje to litery, `?`
otwiera pomoc, `q` kończy:

```
CATEGORIES   37 modules
  1  Obraz i system plików
  2  Konta i hasła
  3  Aplikacje
  4  Oś czasu i sesje
  5  Narzędzia
  6  Raporty i weryfikacja

ACTIONS
  v  Weryfikacja case'u (pełny przebieg)
  r  Raport z sesji
  s  Wyniki tej sesji
  l  Język
  m  Sekrety
  ?  Pomoc
  q  Wyjście
```

Wpisz numer kategorii, żeby zobaczyć jej moduły, potem wybierz moduł. Menu
tekstowe działa po SSH i w każdym terminalu; curses dodaje nawigację strzałkami i
panel szczegółów. Oba dopasowują się do szerokości terminala i zamieniają
znaki, których terminal nie umie rysować, na ASCII.

### Uruchomienie pojedynczego modułu

Każdy moduł działa nieinteraktywnie, co jest tym, czego chcesz przy powtarzalnych
przebiegach albo przy skryptowaniu sekwencji:

```bash
./forensic.py --cli free_space
./forensic.py --cli carve --param scan=full
./forensic.py --cli blockmap --param block=1074732
./forensic.py --cli report
```

`--param KLUCZ=WARTOŚĆ` można powtarzać. Uruchomiony bez wymaganego parametru
moduł powie, którego brakuje. `find_string` potrzebuje czegoś do szukania:

```bash
./forensic.py --cli find_string --param text=nazwisko --param limit=50
```

## Konfiguracja

`config.toml` powstaje przy pierwszym uruchomieniu, obok danych, i trzyma ścieżkę
obrazu, punkt montowania, katalog roboczy, katalog EDL, nazwę case'u, język i
przełącznik odsłaniania sekretów:

```toml
image = "/path/to/userdata.img"
mountpoint = "/mnt/forensic"
workdir = "/path/to/work"
edl_dir = "/path/to/edl"
case = "redmi3"
lang = "pl"
```

`image` i `edl_dir` są w świeżym checkoutzie **puste** — repozytorium nie może
nieść ścieżki do cudzego materiału dowodowego. Wpisz je tutaj albo podawaj
`--image` i `--edl-dir` przy uruchomieniu. `case` domyślnie wynosi `default`;
plik case'a urządzenia referencyjnego to `redmi3`.

Każdą wartość można nadpisać przy uruchomieniu: `--image`, `--mountpoint`,
`--workdir`, `--edl-dir`, `--case`, `--lang`.

## Moduły

37 modułów w sześciu kategoriach. Każdy czyta obraz, zapisuje findings do
katalogu roboczego i wypisuje podsumowanie; żaden nie zapisuje w obrazie.

**Wyjątkiem jest `mount_ro`, i warto wiedzieć dlaczego.** Wszystkie pozostałe
moduły czytają obraz własnym parserem ext4 tego projektu
(`forensic/core/ext4.py`) — dlatego całe narzędzie działa jako zwykły użytkownik,
bez żadnych uprawnień. `mount_ro` oddaje obraz *jądrowi*, więc jest jedynym
miejscem, w którym niezaufane dane parsuje kod pisany do czego innego. Wymaga
root'a albo sudo bez hasła i montuje z opcjami
`ro,loop,norecovery,nodev,nosuid,noexec` — te trzy dodatkowe flagi niczego nie
kosztują przy montowaniu tylko do odczytu, a zamykają sposoby, w jakie zamontowany
obraz dowodowy mógłby zostać wykorzystany przeciwko maszynie, która go bada. Zostaw
to wyłączone, chyba że potrzebujesz drugiego zdania od jądra; `ext4_selftest`
i `decoder_audit` dają weryfikację krzyżową bez roota.

### Obraz i system plików

| moduł | co daje |
|---|---|
| `image_info` | superblock, geometria, cechy, stan systemu plików, UUID, SHA-256, wykrycie tablicy partycji, inwentaryzacja atrybutów rozszerzonych |
| `mount_ro` | opcjonalne montowanie obrazu tylko do odczytu, z automatycznym odmontowaniem |
| `fs_check` | sprawdzenie spójności (`e2fsck -fn`); nigdy nie naprawia |
| `tsk_crosscheck` | drugie zdanie od The Sleuth Kit: geometria, drzewo plików, metadane inodów, zawartość plików bajt w bajt oraz to, co on widzi, a to narzędzie nie |
| `ext4_selftest` | buduje obrazy ext2/ext4 i sprawdza wobec nich czytnik, żeby rodzina wolumenów, którą czytnik obsługuje źle, pokazała się jako odmowa, a nie jako złe dane |
| `blockmap` | offset w obrazie → plik i pozycja w nim, w obu kierunkach |
| `find_string` | przeszukanie całego obrazu pod sznakiem, z offsetami, hexdumpem i plikiem, do którego należy trafienie |
| `extract_file` | skopiowanie pliku z obrazu razem z plikami `-wal`, `-journal` i `-shm` do manifestu |
| `sqlite_info` | nagłówek bazy, kontrola integralności, tabele, liczby wierszy, pliki towarzyszące |
| `deleted_files` | inody ze znacznikiem usunięcia: co usunięto, kiedy, jak duże — i dlaczego bajty są nieosiągalne |
| `free_space` | przestrzeń nieprzydzielona: rozmiar, liczba luk, długość najdłuższej, ile w niej nie jest zerami |
| `carve` | nazwy usuniętych plików z bloków katalogowych oraz kandydaci na treść z przestrzeni nieprzydzielonej, z oceną, jak daleko każdego dało się zweryfikować |

### Konta i hasła

| moduł | co daje |
|---|---|
| `accounts_db` | konta urządzenia, zapisane poświadczenie według autentykatora, terminy ważności tokenów |
| `authtoken_journal` | tokeny OAuth2 odzyskane z journalu wycofania z wyzerowanym nagłówkiem |
| `login_data` | magazyn haseł przeglądarki oraz werdykt, czy zapisana wartość jest naprawdę zaszyfrowana, czy tylko nieczytelna |
| `cookies_webview` | magazyny ciasteczek, sesyjne ciasteczka w jawnej postaci, rozwinięte ciasteczka sesyjne Facebooka |
| `chrome_history` | adresy, wizyty, sesje przeglądania, wpisane zapytania, identyfikatory kont w adresach |
| `pin_recovery` | ustawienia blokady: sól, format klucza i przeszukanie PIN-u offline |

### Aplikacje

| moduł | co daje |
|---|---|
| `messenger` | która baza wciąż trzyma tekst rozmów, zapisane konta, tożsamość E2EE i token autoryzacji |
| `whatsapp` | magazyn wiadomości, dane konta, stan sesji Signal, brakujące klucze keystore — oraz fakt, że nie ma mechanizmu hasła, który można atakować |
| `fb_tokens` | tokeny dostępu Facebooka ze wszystkich magazynów, w których aplikacja je trzyma, z odrzuconym osobno szumem base64 |
| `snapchat` | aplikacja, po której nie zostało prawie nic: wpis w Sklepie Play, kopia systemowa, historia galerii, pusty katalog mediów |
| `app_install_timeline` | oś instalacji i aktualizacji aplikacji, zestawiona z zapisami użycia i z tym, co faktycznie jest na dysku |

### Oś czasu i sesja

| moduł | co daje |
|---|---|
| `fs_timeline` | każdy plik zapisany po wybranym progu: sesja zapisów, jej serie, zrzuty awarii, ostatnie zapisy przed wyłączeniem |
| `login_timeline` | ostatnie **uwierzytelnienie** i ostatnia **aktywność** każdego konta, z grantów tokenów, znaczników aplikacji i logów sklepów |
| `unlock_proof` | dowód, że urządzenie było odblokowane, stan blokady i czy poświadczenie się zmieniło |
| `session_system` | strona systemowa sesji: historia awarii, rejestry restartu jądra, migawki procesów, liczniki ruchu, logi diagnostyczne |
| `net_state` | czy urządzenie miało sieć: lease DHCP, liczniki ruchu, stan usługi push, wiek tokenów |
| `wifi_creds` | zapisane sieci i klucze WPA z obu miejsc, gdzie Android je trzyma, porównane ze sobą |
| `clock_anomaly` | którym znacznikom czasu można ufać: artefakty epoki systemu plików, stałe instalatora, spójne zakresy dat |
| `mactime_export` | obraz jako body file, czyli inwentarz w formacie czytanej przez narzędzia osi czasu |

### Narzędzia

| moduł | co daje |
|---|---|
| `edl_acquire` | plan odczytu dla zewnętrznego toolchainu akwizycyjnego: geometria partycji i dokładna linia poleceń |
| `find_string` | patrz wyżej — przeszukiwanie całego obrazu z przypisaniem trafień do plików |
| `mount_ro` | patrz wyżej — opcjonalne montowanie tylko do odczytu |

### Raporty i weryfikacja

| moduł | co daje |
|---|---|
| `report` | buduje dokument: obraz, werdykty z dowodami, tabela kont, znalezione sekrety, ostatnia sesja, wiarygodność dat, źródła i brakujące źródła |
| `verify` | uruchamia case i porównuje findings z wartościami potwierdzonymi wcześniej |
| `newcase` | zapisuje case dla nieznanego obrazu, z wartościami `TODO`, żeby pierwsza weryfikacja zgłosiła, czego brakuje |
| `secret_audit` | skanuje artefakty pod kątem sekretów w jawnej postaci i sprawdza, czy polityka maskowania faktycznie zadziałała |
| `decoder_audit` | porównuje własne parsery z implementacjami referencyjnymi, żeby ich wynik nie był tylko spójny sam z sobą |

## Typowa sesja

Przejdź kategorie po kolei. Każdy moduł czyta obraz i dopisuje findings do
case'u; nic nie trzeba powtarzać.

```bash
./install.sh
./forensic.py --preflight
./forensic.py --image /path/to/userdata.img --case redmi3
```

1. **Obraz i system plików** — zacznij od `image_info` po geometrię, potem
   `fs_check` na spójność. `tsk_crosscheck`, jeśli chcesz drugiego czytnika, zanim
   oprzesz się na pierwszym.
2. **Konta i hasła** — `accounts_db`, `login_data`, `cookies_webview`,
   `chrome_history`. Stąd wiesz, czyje to było urządzenie.
3. **Aplikacje** — moduły aplikacji istotnych w danym case'ie. Moduł, który nic
   nie znalazł, i tak raportuje, że nie znalazł — to też jest ustalenie.
4. **Oś czasu i sesja** — `unlock_proof`, `login_timeline`, `fs_timeline`,
   `net_state`, `wifi_creds`, `clock_anomaly`. Stąd wiesz, kiedy urządzenie było
   ostatnio używane i czy datom można wierzyć.
5. **Usunięte dane** — `deleted_files`, `free_space`, `carve`, a `find_string`,
   gdy wiesz, czego szukać.
6. **Raport** — `report` składa wszystko w `work/<case>/reports/report.md`, a
   `verify` czyta obraz ponownie i sprawdza findings wobec pliku case'u.

`edl_acquire` pasuje przed krokiem 1, jeśli obraz dopiero trzeba pozyskać z
urządzenia w trybie EDL; planuje odczyt, zamiast go wykonywać.

Sekrety są maskowane we wszystkim wyjściu. Naciśnij `m` w menu albo uruchom z
`--reveal`, żeby zobaczyć je w jawnej postaci — a `secret_audit` po tym powie, w
których artefaktach jeszcze zostały.

## Case i weryfikacja

Case to plik JSON opisujący obraz plus lista sprawdzeń. Każde sprawdzenie
uruchamia jeden moduł i asertuje wartości wobec jego findings, żeby powtórny
przebieg na tym samym obrazie musiał dać te same liczby:

```json
{ "path": "data.geometry.block_size", "equals": 4096 }
{ "path": "#0.size", "equals": 282624 }
{ "path": "lookups.0.path", "equals": "/data/…/Login Data" }
```

`data.` wskazuje uporządkowany wynik modułu, goły klucz jest szukany we
wszystkich findings, a `#N` przypina odczyt do N-tego findings. Operatory:
`equals`, `contains`, `not_contains`, `matches`, `gte`, `lte`, `in`, `tolerance`.

```bash
./forensic.py --cli newcase --param name=xyz      # cases/xyz.public.json
./forensic.py --cli verify --param scope=image     # obraz i system plików
./forensic.py --cli verify --param scope=accounts  # konta i poświadczenia
./forensic.py --cli verify --param scope=apps      # aplikacje i akwizycja
./forensic.py --cli verify --param scope=timeline  # oś czasu, sesja, sieć, zegar
./forensic.py --cli verify --param scope=full      # wszystko, plus case lokalny
```

`cases/<case>.local.json` leży obok publicznego i nie jest śledzony, żeby
sprawdzenia **o** sekretach zostały poza kontrolą wersji. `scope=full` go
dokłada.

**Wersjonowany plik case'a nie zawiera danych osobowych.** Tam, gdzie wartość
identyfikuje człowieka — UID konta, nazwa profilu, numer telefonu, JID, adres
e-mail — plik publiczny przypina *kształt* wartości asercją `matches`, a
dokładna wartość leży w `cases/<case>.local.json` w zakresie `scope=full`. Case
publiczny nadal zawodzi, gdy moduł zacznie zwracać źle ukształtowany identyfikator
konta, a prawdziwa wartość nadal jest testowana regresją na maszynie, która ten
case ma.

## Testy

```bash
pip install pytest
apt install e2fsprogs          # samotest ext4 buduje własne obrazy
python -m pytest tests/ -q
```

`tests/` obejmuje escapowanie URI SQLite, parser XML `shared_prefs`, nazywanie
wyekstrahowanych plików, domyślne ustawienia konfiguracji i walidatory wyrzeźbiacza.
`tests/test_ext4_selftest.py` woła sam moduł `ext4_selftest`, więc samotest
dostępny z menu jest tym samym kodem, który uruchamia CI. CI uruchamia `ruff check`,
`mypy forensic/core` (blokująco) i `pytest`; `mypy forensic` dla całego pakietu jest
raportowany, ale nie blokuje buildu.

## Gdzie są wyniki

Wszystko trafia pod `work/<case>/`, nigdy do obrazu i nigdy do zainstalowanego
pakietu:

```
work/<case>/
  exports/     findings jako JSON i CSV, jeden plik na moduł
  reports/     report.md — złożony dokument
  extracted/   pliki skopiowane z obrazu, razem z extract_manifest.json
  acquire/     plan akwizycji, wynik i hashes.csv
  cache/       indeks bloków i inne dane do przebudowy
  session.json skumulowane findings, tryb 0600
  secrets.json rejestr wszystkich obsłużonych sekretów, tryb 0600
```

Istnieją dwa manifesty integralności i obejmują różne ground:
`acquire/hashes.csv` to co *pozyskano*, `exports/extract_manifest.json` to co
*wyekstrahowano do analizy*. Plik może wystąpić w obu, a raport wymienia oba,
żeby nic nie policzyć podwójnie.

Findings kumumulują się w `session.json` między przebiegami, więc raport można
budować przez kilka posiedzeń, a nie w jednym.

## Formaty i granice

| format | co dostajesz |
|---|---|
| ext2/3/4 | pełny odczyt: drzewo, metadane, zawartość plików, atrybuty rozszerzone |
| F2FS | pełny odczyt: drzewo, metadane, nieskompresowana zawartość plików. Z odrzuceniem i podaniem powodu dla wolumenów szyfrowanych, plików skompresowanych i plików powyżej ok. 7.9 GiB |
| EROFS | drzewo, metadane i nieskompresowana zawartość. Zawartość plików skompresowanych odrzucona z podaniem powodu |
| squashfs | rozpoznany i odrzucony |

Gdy wolumenu nie da się odczytać, komunikat nazywa format. „To EROFS, którego to
narzędzie nie czyta" i „ten plik jest skompresowany, więc jego zawartość nie jest
dostępna" są odpowiedziami; „nieobsługiwane" nie jest, bo wysyła analityka
szukać problemu, którego tam nie ma.

Inne granice, o których warto wiedzieć, zanim oprzesz się na wyniku:

* Zaszyfrowana kopia WhatsApp jest raportowana jako zaszyfrowana, z wersją i
  nagłówkiem odczytanymi bez klucza. Ładunek zostaje zamknięty i raport to mówi.
* Kandydaci wydobici z przestrzeni nieprzydzielonej mają ocenę: `validated`, gdy
  struktura za sygnaturą została przeszła lub suma przeliczona, `magic`, gdy jest
  tylko sygnatura, `weak` w pozostałych przypadkach, oraz `truncated`, gdy dane
  się urwały. Kandydat nigdy nie jest odzyskanym plikiem i nic nie łączy
  wydobytej nazwy z wydobytym kandydatem.
* Zadeklarowany rozmiar usuniętego pliku jest raportowany, ale ext4 kasuje mapę
  bloków przy usunięciu, więc jego zawartość nie jest osiągalna przez inoda.
  Jedyną drogą jest wydobywanie, a raport rozróżnia te dwie rzeczy.
* Czasy są normalizowane do UTC, a przyjęta jednostka źródłowa jest raportowana,
  bo aplikacje mieszają w jednym pliku sekundy, milisekundy i mikrosekundy od 1601.

## Akwizycja

`edl_acquire` planuje akwizycję, nie wykonuje jej. Tworzy geometrię partycji z
pliku programatora i dokładną linię poleceń dla zewnętrznego toolchainu, domyślnie
na sucho, a model zadania nie ma czasownika, który potrafiłby wyrazić zapis,
wymazanie ani patch — pomyłka w parametrach nie stanie się operacją
destrukcyjną. Uruchomienie odczytu naprawdę wymaga jednocześnie `dry_run=false`
i `confirm=true`.

Każdy przebieg zostawia trzy pliki pod `work/<case>/acquire/`:

| plik | na co odpowiada |
|---|---|
| `edl_<label>.json` | o co się prosiło: plan, geometria, argumenty |
| `acquisition.json` | co się stało: `planned` / `completed` / `partial` / `failed`, czasy, producent |
| `hashes.csv` | co posiadamy: nazwa, źródło, SHA-256, rozmiar, znacznik czasu |

Cztery stany są wyprowadzane z tego, co faktycznie się stało, a nie deklarowane
przez wywołującego. Najważniejszy przypadek to odczyt, który kończy się
niepowodzeniem, ale zostawia plik o planowanym rozmiarze: po samym rozmiarze wygląda
na kompletny, a jest raportowany jako `partial`.

Sam toolchain (`edlclient`) jest osobnym projektem i nie jest częścią tego. Jest
wołany jako program zewnętrzny, nie importowany, a `--preflight` raportuje, czy
jest obecny i czy zastosowano znany lokalny poprawkowy do jego odczytu sektorów.

## Licencja

**GPL-3.0-or-later.** Pełny tekst jest w [`LICENSE`](LICENSE); każdy plik
źródłowy ma nagłówek SPDX, który to mówi, a `pyproject.toml` deklaruje to samo
wyrażenie, więc licencja wędruje razem ze zbudowanym wheelem, a nie tylko
istnieje w tym pliku.

To jest kod tego projektu. Narzędzia, na których stoi, zostają poza nim:

* **The Sleuth Kit** jest też na GPL-3.0 i jest *wołany jako osobny proces*
  przez `tsk_crosscheck` i przez weryfikację krzyżową w `carve` — jego źródła
  nigdy nie są dołączane, ani jedna ich linia nie jest kopiowana. To właśnie
  powód, dla którego warstwa weryfikacji krzyżowej wywołuje proces zamiast
  linkować.
* **`edlclient`** jest zewnętrzne i używane tak samo.
* Wiedza o formatach pochodziła z czytania specyfikacji i z obserwacji zachowania
  narzędzi, nie z kopiowania ich kodu. Nic z `tsk-sources/` ani
  `sleuthkit*/` nigdy nie trafia do repozytorium, a `.gitignore` tego pilnuje.

Przy forkowaniu zostaw nagłówki: to one sprawiają, że licencja wędruje razem
z plikiem, a nie razem z repozytorium.

## Układ katalogów

```
forensic.py              launcher
forensic/cli.py          parsowanie argumentów, wybór frontendu
forensic/controller.py   cykl życia sesji, wywoływanie modułów
forensic/core/           czytniki systemów plików, SQLite, Chromium, AOSP,
                         oś czasu, sekrety, raportowanie, konfiguracja, i18n
forensic/modules/        jeden moduł na zadanie
forensic/ui/             menu, frontend curses, wspólne renderowanie
forensic/verify/         runner case'ów
forensic/acquisition/    preflight, budowa planu odczytu
cases/                   pliki case'ów; *.local.json pozostaje nieśledzony
work/<case>/             wyniki, patrz wyżej
```

`CHANGELOG.md` zapisuje, co zmieniało się między wersjami.
