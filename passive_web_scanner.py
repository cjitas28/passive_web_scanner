#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Herramienta de análisis pasivo de seguridad para sitios web.
Integra múltiples fuentes de información como Shodan, DNSDumpster, etc.
"""

import os
import sys
import json
import time
import socket
import requests
import argparse
import whois
import dns.resolver
import shodan
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from urllib.parse import urlparse

# Inicializamos colorama para formatear salida en consola
init(autoreset=True)

def display_banner():
    """Muestra un banner personalizado al inicio del programa"""
    banner = """
██╗    ██╗███████╗██████╗         ██████╗  █████╗ ███████╗███████╗██╗██╗   ██╗███████╗         ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██║    ██║██╔════╝██╔══██╗        ██╔══██╗██╔══██╗██╔════╝██╔════╝██║██║   ██║██╔════╝         ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝        ██████╔╝███████║███████╗███████╗██║██║   ██║█████╗           ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║███╗██║██╔══╝  ██╔══██╗        ██╔═══╝ ██╔══██║╚════██║╚════██║██║╚██╗ ██╔╝██╔══╝           ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
╚███╔███╔╝███████╗██████╔╝        ██║     ██║  ██║███████║███████║██║ ╚████╔╝ ███████╗         ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝         ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝         ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                                                      by cjitas28
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Herramienta de análisis pasivo para pruebas de seguridad web{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Desarrollado por cjitas28{Style.RESET_ALL}")
    print("-" * 100)

class PassiveScanner:
    """Clase base para el escáner de seguridad pasivo"""
    
    def __init__(self, target, output_dir="results", api_keys=None, port=None):
        """
        Inicializa el escáner con el objetivo y configuraciones
        
        Args:
            target (str): Dominio o IP del objetivo
            output_dir (str): Directorio para guardar resultados
            api_keys (dict): Diccionario con las claves API necesarias
            port (int): Puerto específico para la conexión (opcional)
        """
        # Procesar la URL o dominio para extraer el puerto si está especificado
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            self.domain = parsed_url.netloc
            if ':' in self.domain:
                self.domain, port_str = self.domain.split(':')
                self.port = int(port_str)
            else:
                self.port = 443 if parsed_url.scheme == 'https' else 80
            
            self.scheme = parsed_url.scheme
            self.target_url = target
        else:
            self.domain = target
            self.port = port if port is not None else None
            self.scheme = None
            self.target_url = None
        
        self.target = self.domain
        self.output_dir = output_dir
        self.api_keys = api_keys or {}
        self.results = {
            "target": self.target,
            "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {}
        }
        
        # Crear directorio de resultados si no existe
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        print(f"{Fore.CYAN}[*] Iniciando análisis pasivo para {Fore.YELLOW}{self.target}{Style.RESET_ALL}")
    
    def save_results(self):
        """Guarda los resultados en un archivo JSON"""
        filename = os.path.join(self.output_dir, f"{self.target.replace('.','-')}.json")
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"{Fore.GREEN}[+] Resultados guardados en {filename}{Style.RESET_ALL}")
    
    def make_request(self, url_path="", params=None, headers=None, method="GET"):
        """
        Realiza una solicitud HTTP/HTTPS manejando automáticamente los errores SSL
        
        Args:
            url_path (str): Ruta adicional para añadir a la URL base
            params (dict): Parámetros para la solicitud
            headers (dict): Cabeceras para la solicitud
            method (str): Método HTTP a utilizar
            
        Returns:
            requests.Response: Objeto de respuesta o None si falló
        """
        # Construir la URL base
        if self.target_url:
            base_url = self.target_url
            if not base_url.endswith('/') and url_path and not url_path.startswith('/'):
                base_url += '/'
        else:
            # Si tenemos un puerto específico, lo usamos
            if self.port:
                if self.port == 443:
                    base_url = f"https://{self.target}:{self.port}"
                else:
                    base_url = f"http://{self.target}:{self.port}"
            else:
                # Intentar primero con HTTPS
                base_url = f"https://{self.target}"
        
        # Construir la URL completa
        full_url = f"{base_url}{url_path}"
        
        # Establecer opciones por defecto
        timeout = 10
        standard_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        if headers:
            standard_headers.update(headers)
        
        try:
            # Intentar la solicitud
            response = requests.request(
                method=method,
                url=full_url,
                params=params,
                headers=standard_headers,
                timeout=timeout,
                verify=True
            )
            return response
        except requests.exceptions.SSLError as e:
            # Si falla SSL y estamos usando HTTPS, intentar con HTTP
            if "https://" in full_url:
                try:
                    http_url = full_url.replace("https://", "http://")
                    print(f"{Fore.YELLOW}[!] Error SSL, intentando con HTTP: {http_url}{Style.RESET_ALL}")
                    
                    response = requests.request(
                        method=method,
                        url=http_url,
                        params=params,
                        headers=standard_headers,
                        timeout=timeout,
                        verify=False
                    )
                    return response
                except Exception as http_e:
                    print(f"{Fore.RED}[-] Error al hacer solicitud HTTP: {http_e}{Style.RESET_ALL}")
                    return None
            else:
                print(f"{Fore.RED}[-] Error SSL: {e}{Style.RESET_ALL}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[-] Error al hacer solicitud: {e}{Style.RESET_ALL}")
            return None
    
    def run_all_modules(self):
        """Ejecuta todos los módulos de análisis"""
        print(f"{Fore.CYAN}[*] Ejecutando todos los módulos de análisis{Style.RESET_ALL}")
        
        # WHOIS
        self.get_whois_info()
        
        # DNS
        self.get_dns_info()
        
        # Headers
        self.check_headers()
        
        # Shodan (si tiene API key)
        if 'shodan' in self.api_keys:
            self.query_shodan()
        else:
            print(f"{Fore.YELLOW}[!] No se ha proporcionado API key para Shodan{Style.RESET_ALL}")
        
        # SSL
        self.check_ssl()
        
        # DNSDumpster
        self.query_dnsdumpster()
        
        # Guarda resultados
        self.save_results()
        
        return self.results
    
    def get_whois_info(self):
        """Obtiene información WHOIS del dominio"""
        print(f"{Fore.CYAN}[*] Obteniendo información WHOIS{Style.RESET_ALL}")
        try:
            whois_info = whois.whois(self.target)
            self.results["modules"]["whois"] = {
                "registrar": whois_info.registrar,
                "creation_date": str(whois_info.creation_date),
                "expiration_date": str(whois_info.expiration_date),
                "name_servers": whois_info.name_servers
            }
            print(f"{Fore.GREEN}[+] Información WHOIS obtenida{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error al obtener información WHOIS: {e}{Style.RESET_ALL}")
            self.results["modules"]["whois"] = {"error": str(e)}
    
    def get_dns_info(self):
        """Obtiene registros DNS del dominio"""
        print(f"{Fore.CYAN}[*] Obteniendo información DNS{Style.RESET_ALL}")
        dns_records = {}
        
        try:
            # Intentamos resolver diferentes tipos de registros
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    records = [str(answer) for answer in answers]
                    dns_records[record_type] = records
                    print(f"{Fore.GREEN}[+] Registros {record_type}: {', '.join(records)}{Style.RESET_ALL}")
                except dns.resolver.NoAnswer:
                    print(f"{Fore.YELLOW}[!] No hay registros {record_type}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error al obtener registros {record_type}: {e}{Style.RESET_ALL}")
            
            self.results["modules"]["dns"] = dns_records
        except Exception as e:
            print(f"{Fore.RED}[-] Error general al obtener información DNS: {e}{Style.RESET_ALL}")
            self.results["modules"]["dns"] = {"error": str(e)}
    
    def check_headers(self):
        """Analiza los headers HTTP para detectar información sensible o configuraciones inseguras"""
        print(f"{Fore.CYAN}[*] Analizando headers HTTP{Style.RESET_ALL}")
        try:
            response = self.make_request()
            
            if response:
                # Almacenamos todos los headers
                self.results["modules"]["headers"] = dict(response.headers)
                
                # Comprobamos headers de seguridad
                security_headers = {
                    "Strict-Transport-Security": "Missing HSTS header",
                    "Content-Security-Policy": "Missing CSP header",
                    "X-XSS-Protection": "Missing XSS protection header",
                    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                    "X-Frame-Options": "Missing X-Frame-Options header"
                }
                
                self.results["modules"]["security_headers"] = {}
                
                for header, message in security_headers.items():
                    if header in response.headers:
                        print(f"{Fore.GREEN}[+] {header} está presente: {response.headers[header]}{Style.RESET_ALL}")
                        self.results["modules"]["security_headers"][header] = response.headers[header]
                    else:
                        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
                        self.results["modules"]["security_headers"][header] = "Missing"
                        
                # Comprobamos si hay información sensible en headers
                sensitive_info = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
                for header in sensitive_info:
                    if header in response.headers.keys():
                        print(f"{Fore.YELLOW}[!] Header sensible encontrado: {header}: {response.headers[header]}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] No se pudo realizar la solicitud para analizar headers{Style.RESET_ALL}")
                self.results["modules"]["headers"] = {"error": "No se pudo realizar la solicitud"}
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error al analizar headers: {e}{Style.RESET_ALL}")
            self.results["modules"]["headers"] = {"error": str(e)}
    
    def query_shodan(self):
        """Consulta información en Shodan"""
        print(f"{Fore.CYAN}[*] Consultando Shodan{Style.RESET_ALL}")
        try:
            api = shodan.Shodan(self.api_keys['shodan'])
            # Intentamos resolver la IP si no es ya una dirección IP
            try:
                ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                print(f"{Fore.RED}[-] No se pudo resolver la IP para {self.target}{Style.RESET_ALL}")
                self.results["modules"]["shodan"] = {"error": f"No se pudo resolver la IP para {self.target}"}
                return
                
            result = api.host(ip)
            
            shodan_data = {
                "ip": result.get('ip_str', ''),
                "country": result.get('country_name', ''),
                "os": result.get('os', 'Unknown'),
                "ports": result.get('ports', []),
                "vulns": result.get('vulns', []),
                "hostnames": result.get('hostnames', []),
                "last_update": result.get('last_update', '')
            }
            
            self.results["modules"]["shodan"] = shodan_data
            
            # Imprimimos información básica
            print(f"{Fore.GREEN}[+] IP: {shodan_data['ip']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] País: {shodan_data['country']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] SO: {shodan_data['os']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Puertos: {', '.join(map(str, shodan_data['ports']))}{Style.RESET_ALL}")
            
            # Si hay vulnerabilidades, las mostramos
            if shodan_data['vulns']:
                print(f"{Fore.RED}[!] Vulnerabilidades encontradas: {', '.join(shodan_data['vulns'])}{Style.RESET_ALL}")
        except shodan.APIError as e:
            print(f"{Fore.RED}[-] Error de Shodan API: {e}{Style.RESET_ALL}")
            self.results["modules"]["shodan"] = {"error": str(e)}
        except Exception as e:
            print(f"{Fore.RED}[-] Error al consultar Shodan: {e}{Style.RESET_ALL}")
            self.results["modules"]["shodan"] = {"error": str(e)}
    
    def check_ssl(self):
        """Verifica el certificado SSL del sitio"""
        print(f"{Fore.CYAN}[*] Verificando certificado SSL{Style.RESET_ALL}")
        try:
            # Intentamos una conexión HTTPS
            response = self.make_request()
            
            if response and response.url.startswith('https://'):
                self.results["modules"]["ssl"] = {
                    "has_ssl": True,
                    "valid": True
                }
                print(f"{Fore.GREEN}[+] El sitio tiene SSL/TLS habilitado y válido{Style.RESET_ALL}")
            elif response and response.url.startswith('http://'):
                self.results["modules"]["ssl"] = {
                    "has_ssl": False
                }
                print(f"{Fore.YELLOW}[!] El sitio no tiene SSL/TLS habilitado{Style.RESET_ALL}")
            else:
                self.results["modules"]["ssl"] = {
                    "has_ssl": "unknown",
                    "error": "No se pudo determinar el estado SSL"
                }
                print(f"{Fore.RED}[-] No se pudo determinar el estado SSL{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error al verificar SSL: {e}{Style.RESET_ALL}")
            self.results["modules"]["ssl"] = {"error": str(e)}
    
    def query_dnsdumpster(self):
        """Obtiene información de DNSDumpster (simulada, ya que requiere navegación)"""
        print(f"{Fore.CYAN}[*] Consultando DNSDumpster (simulado){Style.RESET_ALL}")
        # Nota: DNSDumpster no tiene una API oficial, normalmente requeriría scraping
        # Aquí simulamos los resultados para evitar problemas de scraping
        
        self.results["modules"]["dnsdumpster"] = {
            "note": "Esta es una simulación. DNSDumpster no tiene API oficial y requeriría web scraping"
        }
        
        print(f"{Fore.YELLOW}[!] Para obtener resultados de DNSDumpster, visita manualmente: https://dnsdumpster.com/{Style.RESET_ALL}")


class WebSecurityScanner(PassiveScanner):
    """Clase extendida con funcionalidades adicionales de seguridad web"""
    
    def __init__(self, target, output_dir="results", api_keys=None, check_waf=True, port=None):
        """
        Inicializa el escáner de seguridad web
        
        Args:
            target (str): Dominio o IP del objetivo
            output_dir (str): Directorio para guardar resultados
            api_keys (dict): Diccionario con las claves API necesarias
            check_waf (bool): Indica si se debe comprobar WAF
            port (int): Puerto específico para la conexión (opcional)
        """
        super().__init__(target, output_dir, api_keys, port)
        self.check_waf = check_waf
    
    def run_all_modules(self):
        """Ejecuta todos los módulos, incluyendo los específicos de web"""
        # Ejecuta los módulos de la clase base
        super().run_all_modules()
        
        # Módulos adicionales para seguridad web
        self.check_robots()
        self.detect_cms()
        self.check_for_breaches()
        
        if self.check_waf:
            self.detect_waf()
        
        # Guarda los resultados actualizados
        self.save_results()
        
        return self.results
    
    def check_robots(self):
        """Verifica el archivo robots.txt"""
        print(f"{Fore.CYAN}[*] Verificando robots.txt{Style.RESET_ALL}")
        try:
            response = self.make_request("/robots.txt")
            
            if response and response.status_code == 200:
                # Parseamos el contenido para encontrar rutas sensibles
                lines = response.text.split('\n')
                disallowed = [line.split(': ')[1] for line in lines if line.lower().startswith('disallow:')]
                
                self.results["modules"]["robots_txt"] = {
                    "found": True,
                    "content": response.text,
                    "disallowed_paths": disallowed
                }
                
                print(f"{Fore.GREEN}[+] Archivo robots.txt encontrado{Style.RESET_ALL}")
                if disallowed:
                    print(f"{Fore.YELLOW}[!] Rutas restringidas: {', '.join(disallowed)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No se encontró robots.txt{Style.RESET_ALL}")
                self.results["modules"]["robots_txt"] = {"found": False}
        except Exception as e:
            print(f"{Fore.RED}[-] Error al verificar robots.txt: {e}{Style.RESET_ALL}")
            self.results["modules"]["robots_txt"] = {"error": str(e)}
    
    def detect_cms(self):
        """Intenta detectar el CMS utilizado"""
        print(f"{Fore.CYAN}[*] Detectando CMS{Style.RESET_ALL}")
        try:
            response = self.make_request()
            
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                cms_signatures = {
                    "WordPress": [
                        "wp-content", "wp-includes", "wp-login", 
                        '<meta name="generator" content="WordPress'
                    ],
                    "Joomla": [
                        "com_content", "com_users", "com_contact", 
                        '<meta name="generator" content="Joomla'
                    ],
                    "Drupal": [
                        "sites/all", "drupal.js", "drupal.min.js",
                        '<meta name="Generator" content="Drupal'
                    ],
                    "Magento": [
                        "skin/frontend", "magento", "Mage.Cookies",
                        '<script type="text/x-magento-init"'
                    ],
                    "PrestaShop": [
                        "prestashop", "/themes/",
                        '<meta name="generator" content="PrestaShop'
                    ]
                }
                
                detected_cms = None
                confidence = 0
                
                for cms, signatures in cms_signatures.items():
                    matches = 0
                    for signature in signatures:
                        if signature in response.text:
                            matches += 1
                    
                    if matches > confidence:
                        confidence = matches
                        detected_cms = cms
                
                if detected_cms:
                    confidence_level = (confidence / len(cms_signatures[detected_cms])) * 100
                    print(f"{Fore.GREEN}[+] CMS detectado: {detected_cms} (confianza: {confidence_level:.1f}%){Style.RESET_ALL}")
                    self.results["modules"]["cms"] = {
                        "name": detected_cms,
                        "confidence": confidence_level
                    }
                else:
                    print(f"{Fore.YELLOW}[!] No se pudo detectar el CMS{Style.RESET_ALL}")
                    self.results["modules"]["cms"] = {"detected": False}
                    
                # Buscamos versiones en meta tags
                meta_generator = soup.find("meta", {"name": "generator"})
                if meta_generator and "content" in meta_generator.attrs:
                    print(f"{Fore.GREEN}[+] Meta generator: {meta_generator['content']}{Style.RESET_ALL}")
                    self.results["modules"]["cms"]["meta_generator"] = meta_generator["content"]
            else:
                print(f"{Fore.RED}[-] No se pudo realizar la solicitud para detectar CMS{Style.RESET_ALL}")
                self.results["modules"]["cms"] = {"error": "No se pudo realizar la solicitud"}
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error al detectar CMS: {e}{Style.RESET_ALL}")
            self.results["modules"]["cms"] = {"error": str(e)}
    
    def detect_waf(self):
        """Intenta detectar si el sitio está protegido por un WAF"""
        print(f"{Fore.CYAN}[*] Detectando WAF{Style.RESET_ALL}")
        try:
            # Probamos con una solicitud que podría activar un WAF
            headers = {
                'X-Scan-Signature': 'test'
            }
            
            response = self.make_request("/index.php?id=1'", headers=headers, method="GET")
            
            if response:
                # Verificamos firmas comunes de WAF
                waf_signatures = {
                    "Cloudflare": ["CF-RAY", "__cfduid", "cloudflare"],
                    "ModSecurity": ["ModSecurity", "mod_security", "NOYB"],
                    "Akamai": ["AkamaiGHost", "X-Akamai-Transformed"],
                    "Incapsula": ["incap_ses", "_Incapsula_"],
                    "AWS WAF": ["x-amzn-waf", "X-AMZ-WAF"],
                    "F5 BIG-IP ASM": ["TS", "BigIP"],
                    "Sucuri": ["sucuri", "cloudproxy"],
                    "Barracuda": ["barracuda"]
                }
                
                detected_wafs = []
                
                # Verificar encabezados
                for waf, signatures in waf_signatures.items():
                    for signature in signatures:
                        # Verificar en encabezados
                        for header, value in response.headers.items():
                            if signature.lower() in header.lower() or signature.lower() in value.lower():
                                detected_wafs.append(waf)
                                break
                        
                        # Verificar en cookies
                        for cookie in response.cookies:
                            if signature.lower() in cookie.name.lower() or signature.lower() in cookie.value.lower():
                                detected_wafs.append(waf)
                                break
                                
                        # Verificar en body si hay un bloqueo
                        if response.status_code in [403, 406, 501] and signature.lower() in response.text.lower():
                            detected_wafs.append(waf)
                            break
                
                # Eliminar duplicados
                detected_wafs = list(set(detected_wafs))
                
                if detected_wafs:
                    print(f"{Fore.GREEN}[+] WAF detectado: {', '.join(detected_wafs)}{Style.RESET_ALL}")
                    self.results["modules"]["waf"] = {
                        "detected": True,
                        "names": detected_wafs
                    }
                else:
                    print(f"{Fore.YELLOW}[!] No se detectó WAF{Style.RESET_ALL}")
                    self.results["modules"]["waf"] = {"detected": False}
            else:
                print(f"{Fore.RED}[-] No se pudo realizar la solicitud para detectar WAF{Style.RESET_ALL}")
                self.results["modules"]["waf"] = {"error": "No se pudo realizar la solicitud"}
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error al detectar WAF: {e}{Style.RESET_ALL}")
            self.results["modules"]["waf"] = {"error": str(e)}
    
    def check_for_breaches(self):
        """Verifica si el dominio ha aparecido en brechas de seguridad conocidas"""
        print(f"{Fore.CYAN}[*] Verificando brechas de datos conocidas{Style.RESET_ALL}")
        
        # Nota: Idealmente se usaría la API de Have I Been Pwned, pero requiere clave
        # Simulamos una comprobación básica
        
        try:
            # Una implementación real requeriría una API key para Have I Been Pwned
            self.results["modules"]["breaches"] = {
                "note": "Para verificar brechas reales, visita https://haveibeenpwned.com/"
            }
            
            print(f"{Fore.YELLOW}[!] Para verificar brechas de datos, visita: https://haveibeenpwned.com/DomainSearch{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error al verificar brechas: {e}{Style.RESET_ALL}")
            self.results["modules"]["breaches"] = {"error": str(e)}


def main():
    """Función principal para ejecutar el escáner desde línea de comandos"""
    # Mostrar el banner personalizado
    display_banner()
    
    parser = argparse.ArgumentParser(description="Herramienta de escaneo pasivo de seguridad web")
    parser.add_argument("target", help="Dominio o URL objetivo")
    parser.add_argument("-o", "--output", default="results", help="Directorio de salida para resultados")
    parser.add_argument("--shodan-key", help="API Key para Shodan")
    parser.add_argument("--no-waf", action="store_true", help="Desactivar detección de WAF")
    args = parser.parse_args()
    
    # Preparamos las API keys
    api_keys = {}
    if args.shodan_key:
        api_keys['shodan'] = args.shodan_key
    
    # Creamos el escáner
    scanner = WebSecurityScanner(
        target=args.target,
        output_dir=args.output,
        api_keys=api_keys,
        check_waf=not args.no_waf
    )
    
    # Ejecutamos todos los módulos
    scanner.run_all_modules()
    
    print(f"\n{Fore.CYAN}[*] Escaneo completado. Resultados guardados en {args.output}/{args.target.replace('.','-')}.json{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}WEB_PASSIVE_SCANNER by cjitas28 - Gracias por usar esta herramienta{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
