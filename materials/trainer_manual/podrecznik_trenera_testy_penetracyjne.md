# Podręcznik Trenera - Testy Penetracyjne
## Kompleksowy przewodnik szkoleniowy

---

## Spis treści

1. [Wprowadzenie do testów penetracyjnych](#1-wprowadzenie-do-testów-penetracyjnych)
2. [Standardy OSSTMM i OWASP](#2-standardy-osstmm-i-owasp)
3. [Dobre praktyki NIST i CIS](#3-dobre-praktyki-nist-i-cis)
4. [Różnice między testami penetracyjnymi a audytami bezpieczeństwa](#4-różnice-między-testami-penetracyjnymi-a-audytami-bezpieczeństwa)
5. [Organizacja testów penetracyjnych](#5-organizacja-testów-penetracyjnych)
6. [Fazy testu penetracyjnego](#6-fazy-testu-penetracyjnego)
7. [Metody ochrony przed atakami](#7-metody-ochrony-przed-atakami)

---

## 1. Wprowadzenie do testów penetracyjnych

### 1.1 Definicje i podstawowe pojęcia

**Test penetracyjny (pentest)** to symulowany cyberatak przeprowadzany na systemie komputerowym, sieci lub aplikacji w celu zidentyfikowania luk bezpieczeństwa, które mogłyby zostać wykorzystane przez prawdziwych atakujących.

#### Kluczowe pojęcia:
- **Vulnerability Assessment** - ocena podatności
- **Penetration Testing** - test penetracyjny
- **Red Team** - zespół atakujący
- **Blue Team** - zespół obronny
- **Purple Team** - współpraca między zespołami

### 1.2 Rodzaje testów penetracyjnych

#### 1.2.1 Ze względu na poziom wiedzy o systemie:
- **Black Box** - brak wiedzy o systemie
- **White Box** - pełna wiedza o systemie
- **Gray Box** - częściowa wiedza o systemie

#### 1.2.2 Ze względu na zakres:
- **External Testing** - testy zewnętrzne
- **Internal Testing** - testy wewnętrzne
- **Web Application Testing** - testy aplikacji webowych
- **Mobile Application Testing** - testy aplikacji mobilnych
- **Social Engineering** - inżynieria społeczna

### 1.3 Metodologie testów penetracyjnych

#### 1.3.1 OWASP Testing Guide
- Faza 1: Informacje i planowanie
- Faza 2: Modelowanie zagrożeń
- Faza 3: Testowanie automatyczne
- Faza 4: Testowanie manualne
- Faza 5: Raportowanie

#### 1.3.2 PTES (Penetration Testing Execution Standard)
1. Pre-engagement Interactions
2. Intelligence Gathering
3. Threat Modeling
4. Vulnerability Assessment
5. Exploitation
6. Post Exploitation
7. Reporting

### 1.4 Narzędzia do testów penetracyjnych

#### 1.4.1 Narzędzia do skanowania:
- **Nmap** - skanowanie portów i usług
- **Masscan** - szybkie skanowanie portów
- **Zmap** - skanowanie internetu

#### 1.4.2 Narzędzia do testowania aplikacji webowych:
- **Burp Suite** - proxy do testowania aplikacji web
- **OWASP ZAP** - darmowy skaner bezpieczeństwa
- **Nikto** - skaner luk bezpieczeństwa

#### 1.4.3 Narzędzia do eksploitacji:
- **Metasploit** - framework do eksploitacji
- **Exploit-DB** - baza eksploitów
- **Cobalt Strike** - platforma do testów penetracyjnych

---

## 2. Standardy OSSTMM i OWASP

### 2.1 OSSTMM (Open Source Security Testing Methodology Manual)

#### 2.1.1 Wprowadzenie do OSSTMM
OSSTMM to otwarta metodologia testowania bezpieczeństwa, która zapewnia standardowy sposób przeprowadzania testów bezpieczeństwa.

#### 2.1.2 Główne zasady OSSTMM:
- **Operational Security** - bezpieczeństwo operacyjne
- **Physical Security** - bezpieczeństwo fizyczne
- **Wireless Security** - bezpieczeństwo bezprzewodowe
- **Telecommunications Security** - bezpieczeństwo telekomunikacyjne
- **Data Networks Security** - bezpieczeństwo sieci danych

#### 2.1.3 Fazy testowania według OSSTMM:
1. **Phase 1: Pre-engagement** - przygotowanie do testów
2. **Phase 2: Intelligence** - zbieranie informacji
3. **Phase 3: Active Reconnaissance** - aktywny rekonesans
4. **Phase 4: Vulnerability Assessment** - ocena podatności
5. **Phase 5: Penetration Testing** - testy penetracyjne
6. **Phase 6: Reporting** - raportowanie

### 2.2 OWASP (Open Web Application Security Project)

#### 2.2.1 OWASP Top 10 (2021)
1. **A01:2021 – Broken Access Control** - uszkodzona kontrola dostępu
2. **A02:2021 – Cryptographic Failures** - błędy kryptograficzne
3. **A03:2021 – Injection** - ataki typu injection
4. **A04:2021 – Insecure Design** - niebezpieczny projekt
5. **A05:2021 – Security Misconfiguration** - błędna konfiguracja bezpieczeństwa
6. **A06:2021 – Vulnerable and Outdated Components** - podatne i przestarzałe komponenty
7. **A07:2021 – Identification and Authentication Failures** - błędy identyfikacji i uwierzytelniania
8. **A08:2021 – Software and Data Integrity Failures** - błędy integralności oprogramowania i danych
9. **A09:2021 – Security Logging and Monitoring Failures** - błędy logowania i monitorowania bezpieczeństwa
10. **A10:2021 – Server-Side Request Forgery (SSRF)** - fałszowanie żądań po stronie serwera

#### 2.2.2 OWASP Testing Guide
- **Information Gathering** - zbieranie informacji
- **Configuration and Deployment Management Testing** - testowanie konfiguracji
- **Identity Management Testing** - testowanie zarządzania tożsamością
- **Authentication Testing** - testowanie uwierzytelniania
- **Authorization Testing** - testowanie autoryzacji
- **Session Management Testing** - testowanie zarządzania sesjami
- **Input Validation Testing** - testowanie walidacji danych wejściowych
- **Error Handling** - obsługa błędów
- **Cryptography** - kryptografia
- **Business Logic Testing** - testowanie logiki biznesowej
- **Client Side Testing** - testowanie po stronie klienta

---

## 3. Dobre praktyki NIST i CIS

### 3.1 NIST Cybersecurity Framework

#### 3.1.1 Pięć głównych funkcji:
1. **Identify** - identyfikacja
2. **Protect** - ochrona
3. **Detect** - wykrywanie
4. **Respond** - reagowanie
5. **Recover** - odzyskiwanie

#### 3.1.2 Implementacja w testach penetracyjnych:
- **Identify**: Mapowanie zasobów i zagrożeń
- **Protect**: Testowanie mechanizmów ochrony
- **Detect**: Weryfikacja systemów wykrywania
- **Respond**: Testowanie procedur reagowania
- **Recover**: Ocena planów odzyskiwania

### 3.2 CIS Controls (Center for Internet Security)

#### 3.2.1 Główne grupy kontroli:
1. **Basic CIS Controls** (1-6) - podstawowe kontrole
2. **Foundational CIS Controls** (7-16) - kontrole fundamentalne
3. **Organizational CIS Controls** (17-18) - kontrole organizacyjne

#### 3.2.2 Implementacja w testach penetracyjnych:
- **Control 1: Inventory and Control of Enterprise Assets** - inwentaryzacja zasobów
- **Control 2: Inventory and Control of Software Assets** - inwentaryzacja oprogramowania
- **Control 3: Data Protection** - ochrona danych
- **Control 4: Secure Configuration of Enterprise Assets and Software** - bezpieczna konfiguracja
- **Control 5: Account Management** - zarządzanie kontami

---

## 4. Różnice między testami penetracyjnymi a audytami bezpieczeństwa

### 4.1 Testy penetracyjne

#### Charakterystyka:
- **Cel**: Symulacja rzeczywistego ataku
- **Metoda**: Aktywne testowanie systemów
- **Zakres**: Ograniczony do określonych systemów
- **Czas**: Krótki okres (dni/tygodnie)
- **Wynik**: Lista luk bezpieczeństwa z możliwością ich wykorzystania

#### Proces:
1. Planowanie i uzyskanie zgód
2. Rekonesans i zbieranie informacji
3. Identyfikacja luk bezpieczeństwa
4. Próba wykorzystania luk
5. Raportowanie wyników

### 4.2 Audyty bezpieczeństwa

#### Charakterystyka:
- **Cel**: Ocena zgodności z politykami i standardami
- **Metoda**: Przegląd dokumentacji i konfiguracji
- **Zakres**: Szeroki zakres organizacji
- **Czas**: Długi okres (miesiące)
- **Wynik**: Ocena zgodności z wymaganiami

#### Proces:
1. Planowanie audytu
2. Przegląd dokumentacji
3. Weryfikacja implementacji
4. Testowanie zgodności
5. Raportowanie i rekomendacje

### 4.3 Porównanie

| Aspekt | Testy penetracyjne | Audyty bezpieczeństwa |
|--------|-------------------|----------------------|
| **Cel** | Symulacja ataku | Ocena zgodności |
| **Metoda** | Aktywne testowanie | Przegląd dokumentacji |
| **Zakres** | Określone systemy | Cała organizacja |
| **Czas** | Krótki | Długi |
| **Wynik** | Luki + exploitacja | Ocena zgodności |

---

## 5. Organizacja testów penetracyjnych

### 5.1 Prawne aspekty

#### 5.1.1 Wymagane dokumenty:
- **Scope of Work (SOW)** - zakres prac
- **Rules of Engagement (RoE)** - zasady prowadzenia testów
- **Non-Disclosure Agreement (NDA)** - umowa o zachowaniu poufności
- **Authorization Letter** - list autoryzacyjny

#### 5.1.2 Zgody i uprawnienia:
- Zgoda właściciela systemu
- Zgoda administratorów systemu
- Zgoda użytkowników końcowych (jeśli dotyczy)
- Zgoda na testy w godzinach pracy/poza godzinami

### 5.2 Tworzenie planu testów

#### 5.2.1 Elementy planu testów:
1. **Cel i zakres testów**
2. **Metodologia testowania**
3. **Harmonogram testów**
4. **Zespół testowy**
5. **Zasoby wymagane**
6. **Kryteria sukcesu**
7. **Plan komunikacji**
8. **Plan zarządzania ryzykiem**

#### 5.2.2 Przykład struktury planu:

```markdown
# Plan testów penetracyjnych

## 1. Informacje podstawowe
- Nazwa projektu: [Nazwa]
- Data rozpoczęcia: [Data]
- Data zakończenia: [Data]
- Zespół: [Lista członków]

## 2. Zakres testów
- Systemy docelowe: [Lista]
- Wykluczenia: [Lista]
- Ograniczenia: [Lista]

## 3. Metodologia
- Standard: OWASP/OSSTMM
- Narzędzia: [Lista]
- Fazy: [Opis]

## 4. Harmonogram
- Faza 1: [Data] - [Data]
- Faza 2: [Data] - [Data]
- ...

## 5. Raportowanie
- Format: [Format]
- Częstotliwość: [Częstotliwość]
- Odbiorcy: [Lista]
```

### 5.3 Rozwiązywanie problemów

#### 5.3.1 Typowe problemy:
- **Brak dostępu do systemów** - rozwiązanie: wcześniejsze uzgodnienia
- **Ograniczenia czasowe** - rozwiązanie: elastyczny harmonogram
- **Ograniczenia techniczne** - rozwiązanie: alternatywne metody
- **Odpowiedzi systemów** - rozwiązanie: monitoring i komunikacja

#### 5.3.2 Procedury awaryjne:
1. **Zatrzymanie testów** - w przypadku problemów
2. **Komunikacja z klientem** - natychmiastowe powiadomienie
3. **Dokumentacja incydentów** - szczegółowe zapisy
4. **Plan naprawczy** - działania naprawcze

---

## 6. Fazy testu penetracyjnego

### 6.1 Rekonesans i zbieranie informacji

#### 6.1.1 Pasywny rekonesans:
- **OSINT (Open Source Intelligence)** - informacje z otwartych źródeł
- **Google Dorking** - zaawansowane wyszukiwanie w Google
- **Social Media Intelligence** - analiza mediów społecznościowych
- **DNS Enumeration** - wyliczanie rekordów DNS
- **Whois Lookup** - sprawdzanie informacji o domenie

#### 6.1.2 Aktywny rekonesans:
- **Port Scanning** - skanowanie portów
- **Service Detection** - wykrywanie usług
- **OS Fingerprinting** - identyfikacja systemu operacyjnego
- **Vulnerability Scanning** - skanowanie luk bezpieczeństwa

#### 6.1.3 Narzędzia do rekonesansu:
- **Nmap** - skanowanie portów i usług
- **Recon-ng** - framework do rekonesansu
- **theHarvester** - zbieranie informacji z różnych źródeł
- **Maltego** - platforma do analizy danych
- **Shodan** - wyszukiwarka urządzeń internetowych

### 6.2 Identyfikacja słabości i podatności

#### 6.2.1 Typy podatności:
- **Buffer Overflow** - przepełnienie bufora
- **SQL Injection** - wstrzykiwanie SQL
- **Cross-Site Scripting (XSS)** - skrypty między witrynami
- **Cross-Site Request Forgery (CSRF)** - fałszowanie żądań
- **Insecure Direct Object References** - niebezpieczne odwołania do obiektów
- **Security Misconfiguration** - błędna konfiguracja bezpieczeństwa

#### 6.2.2 Metody identyfikacji:
- **Automated Scanning** - automatyczne skanowanie
- **Manual Testing** - testowanie manualne
- **Code Review** - przegląd kodu
- **Configuration Review** - przegląd konfiguracji

#### 6.2.3 Narzędzia do identyfikacji:
- **Nessus** - skaner luk bezpieczeństwa
- **OpenVAS** - otwarty skaner luk
- **Burp Suite** - testowanie aplikacji web
- **OWASP ZAP** - skaner bezpieczeństwa
- **SQLMap** - narzędzie do testowania SQL injection

### 6.3 Praktyczne aspekty przeprowadzania ataków

#### 6.3.1 Etapy ataku:
1. **Initial Access** - początkowy dostęp
2. **Execution** - wykonanie kodu
3. **Persistence** - utrzymanie dostępu
4. **Privilege Escalation** - eskalacja uprawnień
5. **Defense Evasion** - omijanie obrony
6. **Credential Access** - dostęp do poświadczeń
7. **Discovery** - odkrywanie systemu
8. **Lateral Movement** - ruch boczny
9. **Collection** - zbieranie danych
10. **Command and Control** - dowodzenie i kontrola
11. **Exfiltration** - eksfiltracja danych
12. **Impact** - wpływ na system

#### 6.3.2 Techniki ataku:
- **Phishing** - ataki phishingowe
- **Social Engineering** - inżynieria społeczna
- **Malware** - złośliwe oprogramowanie
- **Exploits** - wykorzystanie luk
- **Privilege Escalation** - eskalacja uprawnień

#### 6.3.3 Narzędzia do ataków:
- **Metasploit** - framework do eksploitacji
- **Cobalt Strike** - platforma do testów penetracyjnych
- **Empire** - framework PowerShell
- **Mimikatz** - narzędzie do kradzieży poświadczeń
- **Responder** - narzędzie do ataków na sieć

### 6.4 Techniki ukrywania śladów

#### 6.4.1 Metody ukrywania:
- **Log Tampering** - modyfikacja logów
- **Process Hiding** - ukrywanie procesów
- **File Hiding** - ukrywanie plików
- **Network Hiding** - ukrywanie ruchu sieciowego
- **Anti-Forensics** - techniki anty-forensic

#### 6.4.2 Narzędzia do ukrywania:
- **Timestomp** - modyfikacja znaczników czasowych
- **Slacker** - ukrywanie plików w slack space
- **Anti-Forensics Toolkit** - zestaw narzędzi anty-forensic

### 6.5 Tworzenie raportu

#### 6.5.1 Struktura raportu:
1. **Executive Summary** - podsumowanie wykonawcze
2. **Methodology** - metodologia
3. **Findings** - odkryte luki
4. **Risk Assessment** - ocena ryzyka
5. **Recommendations** - rekomendacje
6. **Remediation** - plan naprawczy
7. **Appendices** - załączniki

#### 6.5.2 Elementy raportu:
- **Opis luki** - szczegółowy opis
- **Poziom ryzyka** - ocena ryzyka
- **Dowód koncepcji** - proof of concept
- **Rekomendacje** - zalecenia naprawcze
- **Harmonogram naprawy** - plan działań

---

## 7. Metody ochrony przed atakami

### 7.1 Honeypoty

#### 7.1.1 Definicja i typy:
- **Honeypot** - pułapka na atakujących
- **Honeynet** - sieć honeypotów
- **Honeytoken** - token pułapka

#### 7.1.2 Typy honeypotów:
- **Low-interaction** - niska interakcja
- **High-interaction** - wysoka interakcja
- **Production** - produkcyjne
- **Research** - badawcze

#### 7.1.3 Implementacja:
- **Kippo** - honeypot SSH
- **Dionaea** - honeypot malware
- **Cowrie** - honeypot SSH/Telnet
- **T-Pot** - platforma honeypotów

### 7.2 Systemy IDS/IPS

#### 7.2.1 IDS (Intrusion Detection System):
- **Signature-based** - oparte na sygnaturach
- **Anomaly-based** - oparte na anomaliach
- **Behavior-based** - oparte na zachowaniu

#### 7.2.2 IPS (Intrusion Prevention System):
- **Network-based** - oparte na sieci
- **Host-based** - oparte na hoście
- **Application-based** - oparte na aplikacji

#### 7.2.3 Implementacja:
- **Snort** - system IDS/IPS
- **Suricata** - system IDS/IPS
- **OSSEC** - system HIDS
- **Bro/Zeek** - analizator ruchu sieciowego

### 7.3 Hardening systemów

#### 7.3.1 Hardening Windows:
- **Usuwanie niepotrzebnych usług**
- **Konfiguracja firewall**
- **Aktualizacje bezpieczeństwa**
- **Konfiguracja UAC**
- **Audit policy**
- **Registry hardening**

#### 7.3.2 Hardening Linux:
- **Usuwanie niepotrzebnych pakietów**
- **Konfiguracja iptables**
- **Aktualizacje bezpieczeństwa**
- **Konfiguracja SELinux/AppArmor**
- **Auditd configuration**
- **Kernel hardening**

#### 7.3.3 Narzędzia do hardeningu:
- **CIS-CAT** - narzędzie do oceny zgodności z CIS
- **Lynis** - narzędzie do hardeningu Linux
- **Windows Security Compliance Toolkit** - narzędzie Microsoft
- **Ansible** - automatyzacja konfiguracji

---

## Podsumowanie

Ten podręcznik stanowi kompleksowy przewodnik dla trenerów prowadzących szkolenia z zakresu testów penetracyjnych. Zawiera zarówno teorię, jak i praktyczne aspekty, które pozwolą na skuteczne przekazanie wiedzy uczestnikom szkoleń.

### Kluczowe elementy do zapamiętania:

1. **Testy penetracyjne to symulacja rzeczywistych ataków** - celem jest identyfikacja luk bezpieczeństwa
2. **Standardy i frameworki** - OSSTMM, OWASP, NIST, CIS zapewniają strukturę i metodologię
3. **Prawne aspekty** - zawsze wymagana jest odpowiednia dokumentacja i zgody
4. **Fazy testów** - od rekonesansu po raportowanie, każda faza ma swoje znaczenie
5. **Ochrona** - honeypoty, IDS/IPS i hardening to kluczowe elementy obrony

### Następne kroki:
- Przejrzyj materiały ćwiczeniowe
- Zapoznaj się z przykładami i case studies
- Przygotuj prezentacje dla poszczególnych modułów
- Zaplanuj sesje praktyczne z uczestnikami

---

*Ten podręcznik jest częścią kompleksowego zestawu materiałów szkoleniowych do testów penetracyjnych.*