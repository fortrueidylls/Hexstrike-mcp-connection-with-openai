Wymagania wstępne

    HexStrike MCP Backend (hexstrike-ai - uruchomiony serwer hexstrike_server.py)
    Python 3.9+ (adapter MCP)
    Ngrok (opcjonalnie, jeśli chcesz wystawić serwer poza localhost)
    OpenAI Agent Builder z dostępem do narzędzi MCP
Uruchamianie krok po kroku

1. Uruchom HexStrike MCP 


git clone https://github.com/0x4m4/hexstrike-ai.git
cd hexstrike-ai


python3 -m venv hexstrike-env
source hexstrike-env/bin/activate  # Linux/Mac
# hexstrike-env\Scripts\activate   # Windows


pip3 install -r requirements.txt


python3 hexstrike_server.py --port 8888

    Serwer powinien wystartować na porcie 8888 (lub innym, zgodnie z parametrami).


2. Uruchom Adapter MCP

W tym samym repozytorium uruchom adapter 

python3 hexstrike_mcp_adapter.py

Parametry domyślne:

    MCP Adapter słucha na porcie 9999 (http://127.0.0.1:9999/mcp)
    HexStrike Backend: http://127.0.0.1:8888

Jeśli korzystasz z ngroka, możesz wystawić również MCP:

ngrok http 9999

⚙️ Konfiguracja (jeśli potrzeba)

    Możesz ustawić adres MCP backendu (HexStrike) i adaptera przez zmienne środowiskowe lub edytując kod (aktualizacja HEXSTRIKE_BACKEND itd.).
    Całość działa domyślnie BEZ AUTORYZACJI i jest niezabezpieczona!

3. Połącz z OpenAI Agent Builder

W OpenAI Agent Builder:

    Przejdź do Tools → MCP Servers

    Dodaj nowy serwer MCP podając URL adaptera, np.:

    http://url_z_ngroka/mcp

    (lub adres z ngroka, jeśli łączysz się zdalnie)

    Zapisz.

 Przykład użycia (przepływ działania)

    W interfejsie OpenAI, wybierz swojego agenta/utility.
    Wpisz zapytanie, np.:

    Przeskanuj domenę example.com: poproszę otwarte porty + subdomeny.

    Adapter MCP przekaże zapytanie do HexStrike backend (wywołując odpowiednie narzędzie: np. nmap, subfinder), po czym wynik zostanie zwrócony w oknie UI OpenAI.

 Przykładowe logi

* Running on http://127.0.0.1:9999
✅ MCP Server URL: http://127.0.0.1:9999/mcp
🔗 Hexstrike Backend: http://127.0.0.1:8888
INFO:__main__:MCP Request: method=initialize, params=...

HexStrike Server:

[INFO] Server starting on 127.0.0.1:8888
[INFO] 150+ integrated modules | Adaptive AI decision engine active
...
[INFO] 🚀 Command: nmap -sCV -T4 -Pn example.com
[INFO] 📊 Nmap scan completed for example.com
...
[INFO] 📤 STDOUT: Subfinder: .... (lista subdomen)


Chat: Witam
mcppraktyki

Cześć! Aby rozpocząć rekonesans, podaj proszę adres IP lub domenę, którą chciałbyś przeskanować. Po otrzymaniu tej informacji wykonam dla Ciebie skanowanie Nmap (porty i usługi) oraz wyszukiwanie subdomen (Subfinder).

example.com
mcppraktyki

Oto wyniki wykonanych skanów dla domeny example.com:
Skanowanie portów (Nmap)

Adres IP: 23.215.0.138 (Akamai Technologies CDN)
Otwarte porty:

    80/tcp: http – AkamaiGHost (HTTP Acceleration/Mirror service)
    443/tcp: ssl/http – AkamaiGHost (HTTP Acceleration/Mirror service)

Certyfikat SSL: *.example.com (ICANN, ważny do 2026-01-15)
Wykryte subdomeny (fragment listy, bo subfinder wykrył bardzo dużo – ponad 5000)

Przykładowe subdomeny:

    admin.example.com
    mail.example.com
    ftp.example.com
    www.example.com
    root.example.com
    test.example.com
    dev.example.com
    demo.example.com
    staging.example.com
    shop.example.com


