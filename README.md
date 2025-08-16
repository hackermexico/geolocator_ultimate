# geolocator_ultimate
Es una herramienta para hacer geolocalizacion - hecha en python - es multifuente y correlaciona info de multiples fuentes.

GeoLocator Pro Ultimate es una herramienta avanzada de geolocalización que combina más de 20 fuentes diferentes para determinar la ubicación física de una dirección IP o dominio. Esta herramienta está diseñada para profesionales de seguridad, investigadores éticos y equipos de red.

Características Clave
✅ 20+ fuentes de geolocalización

🌐 APIs gratuitas y premium

💾 Base de datos offline (MaxMind GeoLite2)

📊 Análisis de consenso avanzado

⚠️ Detección de amenazas y reputación

📁 Generación de reportes en JSON

🖥️ Interfaz de terminal intuitiva

Configuración inicial
Crea un archivo geolocator_config.ini con tus API keys

USO: python3 geolocator_ultimate.py [TARGET] [OPCIONES]

EJEMPLOS: 
# Consulta básica para una IP
python3 geolocator_ultimate.py 8.8.8.8

# Consulta para un dominio
python3 geolocator_ultimate.py google.com

# Guardar reporte en JSON
python3 geolocator_ultimate.py 1.1.1.1 --save

# Usar configuración personalizada
python3 geolocator_ultimate.py 192.168.1.1 --config mi_config.ini

Nota importante: Siempre obtén el consentimiento apropiado antes de realizar pruebas de geolocalización en redes que no te pertenecen.
