#!/usr/bin/env python3
"""
GeoLocator Pro Ultimate v3.0
Herramienta COMPLETA de geolocalización con 20+ fuentes
Integra APIs gratuitas, premium opcionales y bases de datos offline

Fuentes integradas:
- APIs Gratuitas: IP-API, IPInfo, FreeGeoIP, IPGeolocation, etc.
- APIs Premium (opcionales): MaxMind, IPStack, AbstractAPI, IPLocate, etc.
- Bases de datos offline: GeoLite2 (MaxMind)
- Herramientas del sistema: Whois, Nmap, Traceroute

Autor: OIHEC by p0pc0rninj4 HL:. Desarrollado para investigación ética
Uso: Solo para pruebas autorizadas y investigación legítima
"""

import json
import requests
import socket
import subprocess
import threading
import time
import argparse
import os
import gzip
import urllib.request
import configparser
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import warnings
warnings.filterwarnings("ignore")

# Intentar importar geoip2 para bases de datos offline
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

class Colors:
    """Colores para output terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class GeoLocatorUltimate:
    def __init__(self, config_file=None):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'GeoLocator-Pro/3.0 (Research Tool)'
        })
        self.results = {}
        self.api_keys = {}
        self.load_config(config_file)
        
    def load_config(self, config_file):
        """Carga configuración y API keys desde archivo"""
        if config_file and os.path.exists(config_file):
            config = configparser.ConfigParser()
            config.read(config_file)
            if 'API_KEYS' in config:
                self.api_keys = dict(config['API_KEYS'])
        else:
            # Crear archivo de configuración ejemplo
            self.create_sample_config()
            
    def create_sample_config(self):
        """Crea archivo de configuración de ejemplo"""
        config_content = """# GeoLocator Pro Ultimate - Configuración de API Keys
# Completa las API keys que tengas disponibles
# Las que estén vacías se saltarán automáticamente

[API_KEYS]
# MaxMind GeoIP2 (muy preciso) - https://www.maxmind.com/
maxmind_user_id = 
maxmind_license_key = 

# IPStack (muy bueno) - https://ipstack.com/
ipstack_key = 

# AbstractAPI (buena precisión) - https://www.abstractapi.com/
abstractapi_key = 

# IPLocate (rápido) - https://www.iplocate.io/
iplocate_key = 

# IPGeolocation Premium - https://ipgeolocation.io/
ipgeolocation_key = 

# IPRegistry (completo) - https://ipregistry.co/
ipregistry_key = 

# GeoJS Premium - https://get.geojs.io/
geojs_key = 

# Ipify (simple) - https://www.ipify.org/
ipify_key = 

# IP2Location (preciso) - https://www.ip2location.com/
ip2location_key = 

# KeyCDN (rápido) - https://tools.keycdn.com/geo
keycdn_key = 

# Shodan (dispositivos IoT) - https://shodan.io/
shodan_key = 

# VirusTotal (threat intel) - https://www.virustotal.com/
virustotal_key = 

# AbuseIPDB (reputación) - https://www.abuseipdb.com/
abuseipdb_key = 

# RIPE Stat (datos de red) - https://stat.ripe.net/
ripe_key = 
"""
        try:
            with open('geolocator_config.ini', 'w') as f:
                f.write(config_content)
            print(f"{Colors.YELLOW}[*] Archivo de configuración creado: geolocator_config.ini{Colors.END}")
            print(f"{Colors.YELLOW}[*] Edítalo para añadir tus API keys y mejorar la precisión{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error creando configuración: {e}{Colors.END}")
        
    def print_banner(self):
        """Banner de la herramienta"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
  ██████╗ ███████╗ ██████╗ ██╗      ██████╗  ██████╗ █████╗ ████████╗ ██████╗ ██████╗ 
 ██╔════╝ ██╔════╝██╔═══██╗██║     ██╔═══██╗██╔════╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
 ██║  ███╗█████╗  ██║   ██║██║     ██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
 ██║   ██║██╔══╝  ██║   ██║██║     ██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
 ╚██████╔╝███████╗╚██████╔╝███████╗╚██████╔╝╚██████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
                           ██╗   ██╗██╗     ████████╗██╗███╗   ███╗ █████╗ ████████╗███████╗
                           ██║   ██║██║     ╚══██╔══╝██║████╗ ████║██╔══██╗╚══██╔══╝██╔════╝
                           ██║   ██║██║        ██║   ██║██╔████╔██║███████║   ██║   █████╗  
                           ██║   ██║██║        ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██╔══╝  
                           ╚██████╔╝███████╗   ██║   ██║██║ ╚═╝ ██║██║  ██║   ██║   ███████╗
                            ╚═════╝ ╚══════╝   ╚═╝   ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝
{Colors.END}
{Colors.YELLOW}                    GeoULTIMATE wwww.oihec.com para mas tools y cursos
{Colors.GREEN}                           Developed by OIHEC for Ethical Research & OSINT{Colors.END}
{Colors.PURPLE}                      APIs Gratuitas + Premium Opcionales + DBs Offline{Colors.END}
        """
        print(banner)

    def validate_ip(self, ip):
        """Valida formato de IP"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def resolve_domain(self, domain):
        """Resuelve dominio a IP"""
        try:
            if domain.startswith(('http://', 'https://')):
                domain = urlparse(domain).netloc
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    # ===========================================
    # APIS GRATUITAS (Sin API key requerida)
    # ===========================================
    
    def ipapi_lookup(self, ip):
        """IP-API.com - Muy popular, sin límites estrictos"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipinfo_lookup(self, ip):
        """IPInfo.io - Popular y confiable"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def freegeoip_lookup(self, ip):
        """FreeIPAPI.com"""
        try:
            url = f"https://freeipapi.com/api/json/{ip}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def geojs_lookup(self, ip):
        """GeoJS - Rápido y confiable"""
        try:
            url = f"https://get.geojs.io/v1/ip/geo/{ip}.json"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipwhois_lookup(self, ip):
        """IPWhois.app - Información WHOIS y geo"""
        try:
            url = f"https://ipwhois.app/json/{ip}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipdata_lookup(self, ip):
        """IPData.co - Versión gratuita"""
        try:
            url = f"https://api.ipdata.co/{ip}?api-key=test"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def keycdn_lookup(self, ip):
        """KeyCDN Tools - Gratuito sin API"""
        try:
            url = f"https://tools.keycdn.com/geo.json?host={ip}"
            headers = {'User-Agent': 'keycdn-tools:https://tools.keycdn.com'}
            response = self.session.get(url, headers=headers, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def extreme_ip_lookup(self, ip):
        """Extreme IP Lookup"""
        try:
            url = f"https://extreme-ip-lookup.com/json/{ip}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    # ===========================================
    # APIS PREMIUM (Con API key opcional)
    # ===========================================

    def maxmind_lookup(self, ip):
        """MaxMind GeoIP2 Web Service - MUY PRECISO"""
        if not self.api_keys.get('maxmind_user_id') or not self.api_keys.get('maxmind_license_key'):
            return {"error": "MaxMind API key no configurada"}
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            url = f"https://geoip.maxmind.com/geoip/v2.1/insights/{ip}"
            auth = HTTPBasicAuth(self.api_keys['maxmind_user_id'], self.api_keys['maxmind_license_key'])
            response = self.session.get(url, auth=auth, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipstack_lookup(self, ip):
        """IPStack - Muy popular y preciso"""
        if not self.api_keys.get('ipstack_key'):
            return {"error": "IPStack API key no configurada"}
        try:
            url = f"http://api.ipstack.com/{ip}?access_key={self.api_keys['ipstack_key']}&format=1"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def abstractapi_lookup(self, ip):
        """AbstractAPI - Buena precisión"""
        if not self.api_keys.get('abstractapi_key'):
            return {"error": "AbstractAPI key no configurada"}
        try:
            url = f"https://ipgeolocation.abstractapi.com/v1/?api_key={self.api_keys['abstractapi_key']}&ip_address={ip}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def iplocate_lookup(self, ip):
        """IPLocate.io - Rápido"""
        if not self.api_keys.get('iplocate_key'):
            return {"error": "IPLocate API key no configurada"}
        try:
            url = f"https://www.iplocate.io/api/lookup/{ip}"
            headers = {'X-API-Key': self.api_keys['iplocate_key']}
            response = self.session.get(url, headers=headers, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipgeolocation_premium_lookup(self, ip):
        """IPGeolocation.io Premium"""
        if not self.api_keys.get('ipgeolocation_key'):
            return {"error": "IPGeolocation API key no configurada"}
        try:
            url = f"https://api.ipgeolocation.io/ipgeo?apiKey={self.api_keys['ipgeolocation_key']}&ip={ip}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ipregistry_lookup(self, ip):
        """IPRegistry - Muy completo"""
        if not self.api_keys.get('ipregistry_key'):
            return {"error": "IPRegistry API key no configurada"}
        try:
            url = f"https://api.ipregistry.co/{ip}?key={self.api_keys['ipregistry_key']}"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def ip2location_lookup(self, ip):
        """IP2Location"""
        if not self.api_keys.get('ip2location_key'):
            return {"error": "IP2Location API key no configurada"}
        try:
            url = f"https://api.ip2location.com/v2/?ip={ip}&key={self.api_keys['ip2location_key']}&package=WS25"
            response = self.session.get(url, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    # ===========================================
    # BASES DE DATOS OFFLINE
    # ===========================================

    def download_geolite2_db(self):
        """Descarga base de datos GeoLite2 si no existe"""
        db_dir = "geodb"
        city_db_path = os.path.join(db_dir, "GeoLite2-City.mmdb")
        
        if os.path.exists(city_db_path):
            return city_db_path
        
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        
        print(f"{Colors.YELLOW}[*] Descargando base de datos GeoLite2...{Colors.END}")
        
        # URL de descarga (requiere registro gratuito en MaxMind)
        # Por ahora usamos una copia de GitHub (menos actualizada pero funcional)
        try:
            url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"
            urllib.request.urlretrieve(url, city_db_path)
            print(f"{Colors.GREEN}[+] Base de datos descargada: {city_db_path}{Colors.END}")
            return city_db_path
        except Exception as e:
            print(f"{Colors.RED}[-] Error descargando DB: {e}{Colors.END}")
            return None

    def geolite2_lookup(self, ip):
        """Consulta base de datos GeoLite2 offline"""
        if not GEOIP2_AVAILABLE:
            return {"error": "Librería geoip2 no instalada. Instalar con: pip install geoip2"}
        
        db_path = self.download_geolite2_db()
        if not db_path:
            return {"error": "No se pudo obtener base de datos GeoLite2"}
        
        try:
            with geoip2.database.Reader(db_path) as reader:
                response = reader.city(ip)
                return {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "region": response.subdivisions.most_specific.name,
                    "city": response.city.name,
                    "postal_code": response.postal.code,
                    "latitude": float(response.location.latitude) if response.location.latitude else None,
                    "longitude": float(response.location.longitude) if response.location.longitude else None,
                    "accuracy_radius": response.location.accuracy_radius,
                    "timezone": response.location.time_zone,
                }
        except geoip2.errors.AddressNotFoundError:
            return {"error": "IP no encontrada en base de datos"}
        except Exception as e:
            return {"error": str(e)}

    # ===========================================
    # HERRAMIENTAS DEL SISTEMA
    # ===========================================

    def whois_lookup(self, ip):
        """Ejecuta whois en el sistema"""
        try:
            result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                return {"whois": result.stdout}
            return None
        except Exception:
            return None

    def nmap_lookup(self, ip):
        """Ejecuta nmap con scripts de geolocalización"""
        try:
            cmd = ['nmap', '--script', 'ip-geolocation-*,asn-query', ip, '-oN', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                return {"nmap": result.stdout}
            return None
        except Exception:
            return None

    def traceroute_lookup(self, ip):
        """Ejecuta traceroute para análisis de ruta"""
        try:
            cmd = ['traceroute', '-n', '-m', '15', ip] if os.name != 'nt' else ['tracert', ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {"traceroute": result.stdout} if result.returncode == 0 else None
        except Exception:
            return None

    def shodan_lookup(self, ip):
        """Shodan - Información de dispositivos IoT"""
        if not self.api_keys.get('shodan_key'):
            return {"error": "Shodan API key no configurada"}
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_keys['shodan_key']}"
            response = self.session.get(url, timeout=15)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def virustotal_lookup(self, ip):
        """VirusTotal - Información de amenazas"""
        if not self.api_keys.get('virustotal_key'):
            return {"error": "VirusTotal API key no configurada"}
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {'x-apikey': self.api_keys['virustotal_key']}
            response = self.session.get(url, headers=headers, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def abuseipdb_lookup(self, ip):
        """AbuseIPDB - Reputación de IP"""
        if not self.api_keys.get('abuseipdb_key'):
            return {"error": "AbuseIPDB API key no configurada"}
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': self.api_keys['abuseipdb_key'], 'Accept': 'application/json'}
            params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            return {"error": str(e)}

    def get_all_sources(self, ip):
        """Consulta TODAS las fuentes disponibles"""
        # Fuentes gratuitas (siempre disponibles)
        free_sources = [
            ("IP-API", self.ipapi_lookup),
            ("IPInfo", self.ipinfo_lookup),
            ("FreeGeoIP", self.freegeoip_lookup),
            ("GeoJS", self.geojs_lookup),
            ("IPWhois", self.ipwhois_lookup),
            ("IPData", self.ipdata_lookup),
            ("KeyCDN", self.keycdn_lookup),
            ("ExtremeIP", self.extreme_ip_lookup),
            ("GeoLite2-DB", self.geolite2_lookup),
        ]
        
        # Fuentes premium (solo si hay API keys)
        premium_sources = [
            ("MaxMind-API", self.maxmind_lookup, 'maxmind_user_id'),
            ("IPStack", self.ipstack_lookup, 'ipstack_key'),
            ("AbstractAPI", self.abstractapi_lookup, 'abstractapi_key'),
            ("IPLocate", self.iplocate_lookup, 'iplocate_key'),
            ("IPGeolocation-Pro", self.ipgeolocation_premium_lookup, 'ipgeolocation_key'),
            ("IPRegistry", self.ipregistry_lookup, 'ipregistry_key'),
            ("IP2Location", self.ip2location_lookup, 'ip2location_key'),
            ("Shodan", self.shodan_lookup, 'shodan_key'),
            ("VirusTotal", self.virustotal_lookup, 'virustotal_key'),
            ("AbuseIPDB", self.abuseipdb_lookup, 'abuseipdb_key'),
        ]
        
        # Herramientas del sistema
        system_sources = [
            ("Whois", self.whois_lookup),
            ("Nmap", self.nmap_lookup),
            ("Traceroute", self.traceroute_lookup),
        ]
        
        all_sources = free_sources + system_sources
        
        # Agregar fuentes premium solo si tienen API key
        for name, func, key_name in premium_sources:
            if self.api_keys.get(key_name):
                all_sources.append((name, func))
        
        results = {}
        active_sources = []
        skipped_sources = []
        
        def query_source(name, func):
            try:
                print(f"{Colors.YELLOW}[*] Consultando {name}...{Colors.END}")
                result = func(ip)
                if result and 'error' not in result:
                    results[name] = result
                    active_sources.append(name)
                    print(f"{Colors.GREEN}[+] {name} completado{Colors.END}")
                elif result and 'API key no configurada' in result.get('error', ''):
                    skipped_sources.append(name)
                    print(f"{Colors.BLUE}[~] {name} saltado (sin API key){Colors.END}")
                else:
                    print(f"{Colors.RED}[-] {name} falló{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[-] Error en {name}: {str(e)}{Colors.END}")
        
        # Ejecutar consultas en paralelo
        print(f"\n{Colors.BOLD}[*] Consultando {len(all_sources)} fuentes simultáneamente...{Colors.END}")
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(query_source, name, func) for name, func in all_sources]
            for future in as_completed(futures):
                future.result()  # Esperar a que termine
        
        print(f"\n{Colors.BOLD}[*] Resumen de fuentes:{Colors.END}")
        print(f"  {Colors.GREEN}Activas: {len(active_sources)}{Colors.END}")
        print(f"  {Colors.BLUE}Saltadas (sin API): {len(skipped_sources)}{Colors.END}")
        print(f"  {Colors.RED}Fallaron: {len(all_sources) - len(active_sources) - len(skipped_sources)}{Colors.END}")
        
        if skipped_sources:
            print(f"\n{Colors.BLUE}[i] Para mayor precisión, configura APIs en geolocator_config.ini:{Colors.END}")
            for source in skipped_sources[:5]:  # Mostrar solo los primeros 5
                print(f"    - {source}")
        
        return results

    def analyze_results(self, results):
        """Análisis avanzado y correlación de resultados"""
        analysis = {
            "consensus_location": {},
            "isp_info": {},
            "coordinates": [],
            "confidence": "unknown",
            "threat_info": {},
            "network_info": {},
            "accuracy_scores": {}
        }
        
        # Extraer información común
        countries, cities, regions = [], [], []
        isps, orgs, asns = [], [], []
        coords, timezones, postal_codes = [], [], []
        threats, accuracy_data = {}, {}
        
        for source, data in results.items():
            if isinstance(data, dict) and 'error' not in data:
                
                # Procesar diferentes tipos de respuesta
                if source == "IP-API" and data.get('status') == 'success':
                    countries.append(data.get('country', ''))
                    cities.append(data.get('city', ''))
                    regions.append(data.get('regionName', ''))
                    isps.append(data.get('isp', ''))
                    asns.append(data.get('as', ''))
                    if data.get('lat') and data.get('lon'):
                        coords.append((float(data['lat']), float(data['lon'])))
                    timezones.append(data.get('timezone', ''))
                    postal_codes.append(data.get('zip', ''))
                
                elif source == "IPInfo":
                    if 'country' in data: countries.append(data['country'])
                    if 'city' in data: cities.append(data['city'])
                    if 'region' in data: regions.append(data['region'])
                    if 'org' in data: orgs.append(data['org'])
                    if 'loc' in data:
                        try:
                            lat, lon = data['loc'].split(',')
                            coords.append((float(lat), float(lon)))
                        except: pass
                    if 'timezone' in data: timezones.append(data['timezone'])
                    if 'postal' in data: postal_codes.append(data['postal'])
                
                elif source == "MaxMind-API":
                    # MaxMind tiene estructura más compleja
                    if 'country' in data:
                        countries.append(data['country'].get('names', {}).get('en', ''))
                    if 'city' in data:
                        cities.append(data['city'].get('names', {}).get('en', ''))
                    if 'location' in data:
                        lat, lon = data['location'].get('latitude'), data['location'].get('longitude')
                        if lat and lon:
                            coords.append((float(lat), float(lon)))
                            accuracy_data[source] = data['location'].get('accuracy_radius', 0)
                
                elif source == "GeoLite2-DB":
                    if data.get('country'): countries.append(data['country'])
                    if data.get('city'): cities.append(data['city'])
                    if data.get('region'): regions.append(data['region'])
                    if data.get('latitude') and data.get('longitude'):
                        coords.append((float(data['latitude']), float(data['longitude'])))
                        accuracy_data[source] = data.get('accuracy_radius', 0)
                    if data.get('timezone'): timezones.append(data['timezone'])
                    if data.get('postal_code'): postal_codes.append(data['postal_code'])
                
                elif source == "IPStack":
                    if data.get('country_name'): countries.append(data['country_name'])
                    if data.get('city'): cities.append(data['city'])
                    if data.get('region_name'): regions.append(data['region_name'])
                    if data.get('latitude') and data.get('longitude'):
                        coords.append((float(data['latitude']), float(data['longitude'])))
                    if data.get('zip'): postal_codes.append(data['zip'])
                
                elif source == "Shodan":
                    if 'country_name' in data: countries.append(data['country_name'])
                    if 'city' in data: cities.append(data['city'])
                    if 'isp' in data: isps.append(data['isp'])
                    if 'org' in data: orgs.append(data['org'])
                    if 'latitude' in data and 'longitude' in data:
                        coords.append((float(data['latitude']), float(data['longitude'])))
                
                elif source == "AbuseIPDB":
                    if 'data' in data:
                        abuse_data = data['data']
                        if abuse_data.get('countryCode'): countries.append(abuse_data['countryCode'])
                        threats['abuse_confidence'] = abuse_data.get('abuseConfidencePercentage', 0)
                        threats['usage_type'] = abuse_data.get('usageType', '')
                        threats['is_whitelisted'] = abuse_data.get('isWhitelisted', False)
                
                # Procesamiento genérico para otras fuentes
                else:
                    for key, value in data.items():
                        if key.lower() in ['country', 'country_name'] and value:
                            countries.append(str(value))
                        elif key.lower() in ['city', 'city_name'] and value:
                            cities.append(str(value))
                        elif key.lower() in ['region', 'region_name', 'state'] and value:
                            regions.append(str(value))
                        elif key.lower() in ['isp', 'internet_service_provider'] and value:
                            isps.append(str(value))
                        elif key.lower() in ['org', 'organization'] and value:
                            orgs.append(str(value))
                        elif key.lower() in ['lat', 'latitude'] and value:
                            try:
                                lat_val = float(value)
                                # Buscar longitud correspondiente
                                for k, v in data.items():
                                    if k.lower() in ['lon', 'lng', 'longitude'] and v:
                                        coords.append((lat_val, float(v)))
                                        break
                            except: pass
        
        # Análisis de consenso usando frecuencias ponderadas
        def get_weighted_consensus(items, weights=None):
            if not items:
                return None
            if weights:
                # Aplicar pesos si están disponibles
                weighted_items = []
                for item, weight in zip(items, weights):
                    weighted_items.extend([item] * int(weight))
                items = weighted_items
            # Retornar el elemento más frecuente
            return max(set(items), key=items.count) if items else None
        
        # Determinar consenso con análisis de confianza
        analysis["consensus_location"]["country"] = get_weighted_consensus(countries)
        analysis["consensus_location"]["city"] = get_weighted_consensus(cities)
        analysis["consensus_location"]["region"] = get_weighted_consensus(regions)
        
        # ISP y organización
        if isps or orgs:
            all_providers = isps + orgs
            analysis["isp_info"]["provider"] = get_weighted_consensus(all_providers)
        
        if asns:
            analysis["network_info"]["asn"] = get_weighted_consensus(asns)
        
        # Análisis de coordenadas con clustering básico
        if coords:
            # Calcular centroide ponderado
            if accuracy_data:
                # Usar precisión como peso inverso (menor radio = mayor peso)
                weights = [1.0 / max(accuracy_data.get(source, 50), 1) for source in accuracy_data]
                total_weight = sum(weights)
                if total_weight > 0:
                    avg_lat = sum(c[0] * w for c, w in zip(coords, weights)) / total_weight
                    avg_lon = sum(c[1] * w for c, w in zip(coords, weights)) / total_weight
                else:
                    avg_lat = sum(c[0] for c in coords) / len(coords)
                    avg_lon = sum(c[1] for c in coords) / len(coords)
            else:
                avg_lat = sum(c[0] for c in coords) / len(coords)
                avg_lon = sum(c[1] for c in coords) / len(coords)
            
            analysis["coordinates"] = [avg_lat, avg_lon]
            
            # Calcular dispersión para evaluar confianza
            distances = []
            for lat, lon in coords:
                dist = ((lat - avg_lat) ** 2 + (lon - avg_lon) ** 2) ** 0.5
                distances.append(dist * 111)  # Aproximar a km
            
            avg_distance = sum(distances) / len(distances) if distances else 0
            analysis["coordinate_dispersion_km"] = round(avg_distance, 2)
        
        # Información de amenazas
        if threats:
            analysis["threat_info"] = threats
        
        # Otros datos de consenso
        analysis["consensus_location"]["timezone"] = get_weighted_consensus(timezones)
        analysis["consensus_location"]["postal_code"] = get_weighted_consensus(postal_codes)
        
        # Calcular confianza basada en múltiples factores
        confidence_score = 0
        source_count = len([r for r in results.values() if isinstance(r, dict) and 'error' not in r])
        
        # Factor 1: Número de fuentes
        if source_count >= 8:
            confidence_score += 40
        elif source_count >= 5:
            confidence_score += 30
        elif source_count >= 3:
            confidence_score += 20
        else:
            confidence_score += 10
        
        # Factor 2: Consenso en ubicación
        country_consensus = countries.count(analysis["consensus_location"].get("country", "")) if countries else 0
        city_consensus = cities.count(analysis["consensus_location"].get("city", "")) if cities else 0
        
        if country_consensus >= len(countries) * 0.8:  # 80% de consenso
            confidence_score += 20
        elif country_consensus >= len(countries) * 0.6:  # 60% de consenso
            confidence_score += 15
        
        if city_consensus >= len(cities) * 0.7:  # 70% de consenso en ciudad
            confidence_score += 20
        elif city_consensus >= len(cities) * 0.5:  # 50% de consenso
            confidence_score += 10
        
        # Factor 3: Dispersión de coordenadas
        if analysis.get("coordinate_dispersion_km", float('inf')) < 50:  # < 50km
            confidence_score += 15
        elif analysis.get("coordinate_dispersion_km", float('inf')) < 200:  # < 200km
            confidence_score += 10
        
        # Factor 4: Fuentes premium
        premium_sources = ["MaxMind-API", "IPStack", "GeoLite2-DB"]
        premium_count = sum(1 for ps in premium_sources if ps in results)
        confidence_score += premium_count * 5
        
        # Determinar nivel de confianza
        if confidence_score >= 80:
            analysis["confidence"] = "muy_alta"
        elif confidence_score >= 60:
            analysis["confidence"] = "alta"
        elif confidence_score >= 40:
            analysis["confidence"] = "media"
        elif confidence_score >= 20:
            analysis["confidence"] = "baja"
        else:
            analysis["confidence"] = "muy_baja"
        
        analysis["confidence_score"] = confidence_score
        analysis["source_count"] = source_count
        
        return analysis

    def print_results(self, ip, results, analysis):
        """Imprime resultados con análisis avanzado"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  REPORTE COMPLETO DE GEOLOCALIZACIÓN")
        print(f"{'='*60}{Colors.END}")
        print(f"{Colors.BOLD}🎯 IP Objetivo:{Colors.END} {Colors.YELLOW}{ip}{Colors.END}")
        print(f"{Colors.BOLD}📅 Timestamp:{Colors.END} {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}📊 Fuentes consultadas:{Colors.END} {analysis['source_count']}")
        
        # Análisis de confianza con emoji
        confidence_emojis = {
            "muy_alta": "🟢", "alta": "🔵", "media": "🟡", "baja": "🟠", "muy_baja": "🔴"
        }
        confidence = analysis['confidence']
        emoji = confidence_emojis.get(confidence, "⚪")
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}🔍 ANÁLISIS DE CONSENSO {emoji}{Colors.END}")
        print(f"Confianza: {Colors.BOLD}{emoji} {confidence.upper().replace('_', ' ')} ({analysis['confidence_score']}/100){Colors.END}")
        
        # Ubicación más probable
        if analysis["consensus_location"]:
            print(f"\n{Colors.BOLD}📍 Ubicación más probable:{Colors.END}")
            location_parts = []
            for key, value in analysis["consensus_location"].items():
                if value and key in ['city', 'region', 'country']:
                    label = {"city": "Ciudad", "region": "Región", "country": "País"}[key]
                    print(f"  {label}: {Colors.CYAN}{value}{Colors.END}")
                    location_parts.append(value)
            
            if location_parts:
                full_location = ", ".join(reversed(location_parts))
                print(f"  {Colors.BOLD}Ubicación completa: {Colors.CYAN}{full_location}{Colors.END}")
        
        # Coordenadas con dispersión
        if analysis["coordinates"]:
            lat, lon = analysis["coordinates"]
            print(f"\n{Colors.BOLD}🌐 Coordenadas:{Colors.END}")
            print(f"  Latitud: {Colors.CYAN}{lat:.6f}{Colors.END}")
            print(f"  Longitud: {Colors.CYAN}{lon:.6f}{Colors.END}")
            if "coordinate_dispersion_km" in analysis:
                dispersion = analysis["coordinate_dispersion_km"]
                color = Colors.GREEN if dispersion < 50 else Colors.YELLOW if dispersion < 200 else Colors.RED
                print(f"  Dispersión: {color}{dispersion} km{Colors.END}")
            
            print(f"  {Colors.BLUE}🗺️  Google Maps: https://maps.google.com/?q={lat},{lon}{Colors.END}")
            print(f"  {Colors.BLUE}🛰️  Google Earth: https://earth.google.com/web/@{lat},{lon},10000m{Colors.END}")
        
        # Información de red
        if analysis["isp_info"] or analysis["network_info"]:
            print(f"\n{Colors.BOLD}🌐 INFORMACIÓN DE RED{Colors.END}")
            if analysis["isp_info"].get("provider"):
                print(f"  Proveedor: {Colors.CYAN}{analysis['isp_info']['provider']}{Colors.END}")
            if analysis["network_info"].get("asn"):
                print(f"  ASN: {Colors.CYAN}{analysis['network_info']['asn']}{Colors.END}")
        
        # Información de amenazas
        if analysis["threat_info"]:
            print(f"\n{Colors.BOLD}⚠️  INFORMACIÓN DE AMENAZAS{Colors.END}")
            for key, value in analysis["threat_info"].items():
                if key == "abuse_confidence":
                    color = Colors.RED if value > 75 else Colors.YELLOW if value > 25 else Colors.GREEN
                    print(f"  Confianza de abuso: {color}{value}%{Colors.END}")
                elif key == "usage_type":
                    print(f"  Tipo de uso: {Colors.CYAN}{value}{Colors.END}")
                elif key == "is_whitelisted":
                    status = "Sí" if value else "No"
                    color = Colors.GREEN if value else Colors.YELLOW
                    print(f"  En whitelist: {color}{status}{Colors.END}")
        
        # Resultados detallados por fuente
        print(f"\n{Colors.BOLD}{Colors.PURPLE}📋 RESULTADOS DETALLADOS POR FUENTE{Colors.END}")
        print(f"{Colors.PURPLE}{'─'*60}{Colors.END}")
        
        for source, data in results.items():
            print(f"\n{Colors.BOLD}[{source}]{Colors.END}")
            if isinstance(data, dict):
                if 'error' in data:
                    print(f"  {Colors.RED}❌ Error: {data['error']}{Colors.END}")
                else:
                    # Formatear según el tipo de fuente
                    if source == "IP-API":
                        self.print_ipapi_data(data)
                    elif source == "IPInfo":
                        self.print_ipinfo_data(data)
                    elif source == "GeoLite2-DB":
                        self.print_geolite2_data(data)
                    elif source in ["MaxMind-API", "IPStack"]:
                        self.print_premium_data(data, source)
                    elif source in ["Whois", "Nmap", "Traceroute"]:
                        self.print_text_data(data)
                    elif source in ["Shodan", "VirusTotal", "AbuseIPDB"]:
                        self.print_security_data(data, source)
                    else:
                        # Formato genérico
                        self.print_generic_data(data)

    def print_ipapi_data(self, data):
        """Formatea datos de IP-API"""
        if data.get('status') == 'success':
            fields = [
                ('country', 'País', '🏳️'), ('regionName', 'Región', '📍'), 
                ('city', 'Ciudad', '🏙️'), ('zip', 'Código Postal', '📮'),
                ('lat', 'Latitud', '🌐'), ('lon', 'Longitud', '🌐'),
                ('timezone', 'Zona Horaria', '⏰'), ('isp', 'ISP', '🌐'),
                ('org', 'Organización', '🏢'), ('as', 'ASN', '🔢')
            ]
            for field, label, emoji in fields:
                if field in data and data[field]:
                    print(f"  {emoji} {label}: {Colors.CYAN}{data[field]}{Colors.END}")

    def print_ipinfo_data(self, data):
        """Formatea datos de IPInfo"""
        field_map = {
            'country': ('País', '🏳️'), 'region': ('Región', '📍'),
            'city': ('Ciudad', '🏙️'), 'postal': ('Código Postal', '📮'),
            'loc': ('Coordenadas', '🌐'), 'timezone': ('Zona Horaria', '⏰'),
            'org': ('Organización', '🏢'), 'hostname': ('Hostname', '💻')
        }
        for field, (label, emoji) in field_map.items():
            if field in data and data[field]:
                print(f"  {emoji} {label}: {Colors.CYAN}{data[field]}{Colors.END}")

    def print_geolite2_data(self, data):
        """Formatea datos de GeoLite2"""
        field_map = {
            'country': ('País', '🏳️'), 'city': ('Ciudad', '🏙️'),
            'region': ('Región', '📍'), 'postal_code': ('Código Postal', '📮'),
            'latitude': ('Latitud', '🌐'), 'longitude': ('Longitud', '🌐'),
            'accuracy_radius': ('Radio de precisión', '🎯'), 'timezone': ('Zona Horaria', '⏰')
        }
        for field, (label, emoji) in field_map.items():
            if field in data and data[field] is not None:
                value = f"{data[field]} km" if field == 'accuracy_radius' else data[field]
                print(f"  {emoji} {label}: {Colors.CYAN}{value}{Colors.END}")

    def print_premium_data(self, data, source):
        """Formatea datos de APIs premium"""
        print(f"  {Colors.GREEN}✨ Fuente Premium{Colors.END}")
        # Formato genérico para datos complejos
        self.print_generic_data(data, max_depth=2)

    def print_security_data(self, data, source):
        """Formatea datos de seguridad (Shodan, VirusTotal, etc.)"""
        if source == "AbuseIPDB" and 'data' in data:
            abuse_data = data['data']
            confidence = abuse_data.get('abuseConfidencePercentage', 0)
            color = Colors.RED if confidence > 75 else Colors.YELLOW if confidence > 25 else Colors.GREEN
            print(f"  🛡️  Confianza de abuso: {color}{confidence}%{Colors.END}")
            print(f"  🏷️  Tipo: {Colors.CYAN}{abuse_data.get('usageType', 'N/A')}{Colors.END}")
        elif source == "Shodan":
            if 'ports' in data:
                ports = ', '.join(map(str, data['ports'][:5]))  # Primeros 5 puertos
                print(f"  🔌 Puertos abiertos: {Colors.CYAN}{ports}{Colors.END}")
            if 'os' in data:
                print(f"  💻 OS: {Colors.CYAN}{data['os']}{Colors.END}")
        else:
            self.print_generic_data(data, max_items=5)

    def print_text_data(self, data):
        """Formatea datos de texto (whois, nmap, etc.)"""
        for key, value in data.items():
            print(f"  {Colors.YELLOW}📄 {key.upper()}:{Colors.END}")
            lines = str(value).split('\n')[:15]  # Limitar líneas
            for line in lines:
                if line.strip():
                    print(f"    {line}")
            if len(str(value).split('\n')) > 15:
                print(f"    {Colors.YELLOW}... (output truncado para brevedad){Colors.END}")

    def print_generic_data(self, data, max_items=10, max_depth=1, depth=0):
        """Formato genérico para cualquier tipo de dato"""
        if depth > max_depth:
            return
        
        count = 0
        for key, value in data.items():
            if count >= max_items:
                print(f"  {Colors.YELLOW}... ({len(data) - max_items} campos más){Colors.END}")
                break
            
            if isinstance(value, dict) and depth < max_depth:
                print(f"  {'  ' * depth}📂 {key}:")
                self.print_generic_data(value, max_items, max_depth, depth + 1)
            elif isinstance(value, list) and value:
                print(f"  {'  ' * depth}📋 {key}: {Colors.CYAN}{', '.join(map(str, value[:3]))}{Colors.END}")
            elif value and key not in ['error']:
                # Truncar valores muy largos
                str_value = str(value)
                if len(str_value) > 100:
                    str_value = str_value[:100] + "..."
                print(f"  {'  ' * depth}🔹 {key}: {Colors.CYAN}{str_value}{Colors.END}")
            
            count += 1

    def save_report(self, ip, results, analysis, filename=None):
        """Guarda reporte completo en JSON"""
        if not filename:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"geolocator_report_{ip.replace('.', '_')}_{timestamp}.json"
        
        report = {
            "metadata": {
                "tool": "GeoLocator Pro Ultimate v3.0",
                "target_ip": ip,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "sources_consulted": list(results.keys()),
                "total_sources": len(results)
            },
            "analysis": analysis,
            "raw_results": results,
            "summary": {
                "confidence": analysis['confidence'],
                "most_likely_location": analysis.get('consensus_location', {}),
                "coordinates": analysis.get('coordinates', []),
                "provider": analysis.get('isp_info', {}).get('provider', 'Unknown')
            }
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            print(f"\n{Colors.GREEN}💾 Reporte completo guardado en: {filename}{Colors.END}")
            return filename
        except Exception as e:
            print(f"\n{Colors.RED}❌ Error guardando reporte: {e}{Colors.END}")
            return None

    def run(self, target, save_json=False, config_file=None):
        """Función principal mejorada"""
        if config_file:
            self.load_config(config_file)
        
        self.print_banner()
        
        # Mostrar estado de APIs
        configured_apis = [k for k, v in self.api_keys.items() if v]
        print(f"{Colors.BOLD}🔑 APIs configuradas: {len(configured_apis)}{Colors.END}")
        if configured_apis:
            print(f"  {Colors.GREEN}✅ {', '.join(configured_apis[:5])}{Colors.END}")
            if len(configured_apis) > 5:
                print(f"  {Colors.GREEN}   ... y {len(configured_apis) - 5} más{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}⚠️  Solo fuentes gratuitas disponibles{Colors.END}")
        
        # Validar y resolver target
        if not self.validate_ip(target):
            print(f"{Colors.YELLOW}🔄 No es una IP válida, resolviendo dominio...{Colors.END}")
            resolved_ip = self.resolve_domain(target)
            if not resolved_ip:
                print(f"{Colors.RED}❌ No se pudo resolver el dominio{Colors.END}")
                return
            print(f"{Colors.GREEN}✅ Dominio resuelto: {target} → {resolved_ip}{Colors.END}")
            target = resolved_ip
        
        print(f"\n{Colors.BOLD}🚀 Iniciando geolocalización completa de {target}...{Colors.END}")
        start_time = time.time()
        
        # Obtener datos de TODAS las fuentes
        results = self.get_all_sources(target)
        
        if not results:
            print(f"{Colors.RED}❌ No se obtuvieron resultados de ninguna fuente{Colors.END}")
            return
        
        # Analizar resultados
        print(f"\n{Colors.YELLOW}🧠 Analizando y correlacionando resultados...{Colors.END}")
        analysis = self.analyze_results(results)
        
        elapsed_time = time.time() - start_time
        print(f"{Colors.GREEN}⚡ Análisis completado en {elapsed_time:.2f} segundos{Colors.END}")
        
        # Mostrar resultados
        self.print_results(target, results, analysis)
        
        # Guardar reporte si se solicita
        if save_json:
            report_file = self.save_report(target, results, analysis)
            if report_file:
                print(f"{Colors.BLUE}📊 Análisis detallado disponible en: {report_file}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='GeoLocator Pro Ultimate - Herramienta de Geolocalización con 20+ Fuentes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python3 geolocator_ultimate.py 8.8.8.8
  python3 geolocator_ultimate.py google.com --save
  python3 geolocator_ultimate.py 1.1.1.1 --config mi_config.ini --save
  
Para máxima precisión, configura tus API keys en geolocator_config.ini
        """
    )
    
    parser.add_argument('target', help='IP o dominio a geolocalizar')
    parser.add_argument('-s', '--save', action='store_true', 
                       help='Guardar reporte completo en JSON')
    parser.add_argument('-c', '--config', 
                       help='Archivo de configuración personalizado')
    parser.add_argument('--no-banner', action='store_true', 
                       help='No mostrar banner')
    parser.add_argument('--install-deps', action='store_true',
                       help='Mostrar comandos para instalar dependencias')
    
    args = parser.parse_args()
    
    if args.install_deps:
        print("📦 Para funcionalidad completa, instala:")
        print("pip install requests geoip2 configparser")
        print("\n🗃️ Para base de datos offline:")
        print("pip install geoip2")
        print("\n⚙️ Herramientas del sistema requeridas:")
        print("apt-get install whois nmap traceroute  # Ubuntu/Debian")
        print("yum install whois nmap traceroute      # CentOS/RHEL")
        return
    
    try:
        locator = GeoLocatorUltimate(args.config)
        if args.no_banner:
            locator.print_banner = lambda: None
        locator.run(args.target, args.save, args.config)
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}✨ Geolocalización completada exitosamente{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Operación cancelada por el usuario{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}💥 Error inesperado: {e}{Colors.END}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
