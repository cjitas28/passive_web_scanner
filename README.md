# passive_web_scanner

Herramienta de análisis pasivo de seguridad para sitios web. Integra diferentes módulos que permiten recolectar información valiosa sobre el objetivo mediante consultas a WHOIS, DNS, cabeceras HTTP, Shodan, detección de WAF y CMS.

# Requisitos

 - Python 3.x 
 - Módulos requeridos: requests, argparse, whois,
   dns.resolver, shodan, bs4, colorama, urllib.parse

# Instalacion de dependencias:

>pip install requests argparse python-whois dnspython shodan beautifulsoup4 colorama

## USO
Ejecutar el escáner con un dominio objetivo:
>python we_security_scanner.py example.com

Guardar los resultados en un directorio específico:
>python we_security_scanner.py example.com -o resultados

Ejecutar sin detección de WAF:
>python we_security_scanner.py example.com --no-waf

Usar una clave API de Shodan:
>python we_security_scanner.py example.com --shodan-key TU_API_KEY
## Funcionalidades

### 1. WHOIS Lookup

Obtiene información sobre el dominio como el registrador, fechas de creación y expiración.

### 2. Resolución DNS

Obtiene registros A, AAAA, MX, NS, TXT, SOA y CNAME.

### 3. Análisis de Cabeceras HTTP

Detecta configuraciones inseguras o headers faltantes.

### 4. Consulta a Shodan

Busca información sobre la IP en Shodan (requiere clave API).

### 5. Detección de WAF

Intenta identificar firewalls de aplicación web analizando headers y respuestas HTTP.

### 6. Análisis de robots.txt

Verifica si existen rutas sensibles en `robots.txt`.

### 7. Detección de CMS

Intenta identificar el CMS utilizado mediante patrones en el HTML.

### 8. Verificación de SSL

Comprueba si el sitio usa HTTPS y si el certificado es válido.

### 9. Brechas de Seguridad

Consulta bases de datos públicas para verificar si el dominio ha estado comprometido.
