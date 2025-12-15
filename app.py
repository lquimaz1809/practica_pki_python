from flask import Flask, request
import datetime
import os
import csv
from typing import Tuple, List, Dict, Any

# Creamos la instancia de la aplicación Flask.
app = Flask(__name__)

# Rutas y cabeceras obligatorias para el Bloque 4
LOG_FILE = "/var/log/user_access.log"
LOG_HEADER = ["timestamp", "nombre", "email", "ip"]

def parse_dn(dn: str) -> Tuple[str, str]:
    nombre = "Desconocido"
    email = "No disponible"
    # Ajuste para formato estándar de OpenSSL (ej: /C=ES/CN=Piero...)
    if dn:
        partes = dn.split("/")
        for p in partes:
            p = p.strip()
            if p.startswith("CN="):
                nombre = p.replace("CN=", "", 1)
            elif p.startswith("emailAddress="):
                email = p.replace("emailAddress=", "", 1)
    return nombre, email

# BLOQUE 4A: Sistema de Logging Mejorado - Escritura Robusta
def log_user_access(cn: str, email: str, ip: str):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = [timestamp, cn, email, ip]
    
    file_exists = os.path.exists(LOG_FILE)
    
    try:
        with open(LOG_FILE, 'a', newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                 writer.writerow(LOG_HEADER)
            writer.writerow(log_data)
            
    except PermissionError:
        print(f"ERROR: Permisos insuficientes para escribir en {LOG_FILE}.")
    except Exception as e:
        print(f"ERROR inesperado al escribir en el log: {e}")

# BLOQUE 4A: Lectura Robusta para /admin
def read_user_log() -> Tuple[List[Dict[str, Any]], str]:
    log_entries = []
    error_message = None
    
    try:
        with open(LOG_FILE, 'r', encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None) 
                
            for line_number, row in enumerate(reader):
                if not row: continue # Saltar líneas vacías
                try:
                    timestamp_str, nombre, email, ip = row
                    timestamp_obj = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    
                    log_entries.append({
                        'timestamp': timestamp_obj,
                        'fecha_hora': timestamp_str,
                        'nombre': nombre,
                        'email': email,
                        'ip': ip
                    })
                except ValueError:
                    print(f"Línea mal formateada en el log: {row}")
                    continue 

    except FileNotFoundError:
        error_message = f"El fichero de log no existe o no se puede acceder: {LOG_FILE}"
    except PermissionError:
        error_message = f"Permisos insuficientes para leer el log: {LOG_FILE}"
    except Exception as e:
        error_message = f"Error desconocido al leer el log: {e}"
        
    return log_entries, error_message

@app.route("/")
def index():
    # CAMBIO BLOQUE 3: Usamos SSL_CLIENT_S_DN para coincidir con Nginx y la rúbrica 
    subject_dn = request.headers.get("SSL_CLIENT_S_DN", request.headers.get("SSL_CLIENT_SUBJECT", ""))
    verify = request.headers.get("SSL_CLIENT_VERIFY", "NONE")
    
    if verify != "SUCCESS":
        return f"""Certificado de cliente no válido o no presentado. ({verify})""", 403

    nombre, email = parse_dn(subject_dn)
    ip = request.remote_addr
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Llamada a la función de logging robusto (Bloque 4A)
    log_user_access(nombre, email, ip)

    # BLOQUE 4B: Mejora de la Interfaz Web - Ruta /
    html = f"""
    <html>
        <head>
            <title>Práctica PKI con Python</title>
            <meta charset="utf-8" />
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
                .container {{ background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 600px; margin: auto; }}
                .info-block {{ 
                    background-color: #e0f7fa; 
                    border-left: 5px solid #00bcd4; 
                    padding: 20px; 
                    margin-bottom: 20px; 
                    box-shadow: 2px 2px 5px rgba(0,0,0,0.1); 
                }}
                h1 {{ color: #2e6c80; }}
                ul {{ list-style-type: none; padding: 0; }}
                ul li strong {{ font-weight: normal; margin-right: 5px; color: #333; }}
                .message {{ color: #00796b; font-weight: bold; margin-top: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>¡Autenticación Exitosa!</h1>
                <div class="info-block">
                    <h2>Detalles de su Certificado</h2>
                    <ul>
                        <li><strong>Nombre (CN)</strong>: {nombre}</li>
                        <li><strong>Email</strong>: {email}</li>
                        <li><strong>IP del Cliente</strong>: {ip}</li>
                        <li><strong>Fecha/Hora del Acceso</strong>: {timestamp}</li>
                    </ul>
                </div>
                <p class="message">Has accedido mediante un certificado emitido por la CA del sistema.</p>
                <p><a href="/admin">Ir al Panel de Administración</a> (Solo Superusuarios)</p>
            </div>
        </body>
    </html>
    """
    return html

# BLOQUE 3 y BLOQUE 4B: Panel de Administración
@app.route("/admin")
def admin_panel():
    # --- IMPLEMENTACIÓN BLOQUE 3.1: Verificación interna en Flask ---
    
    # 1. Recuperar cabeceras de Nginx [cite: 33-35]
    verify = request.headers.get("SSL_CLIENT_VERIFY", "NONE")
    subject_dn = request.headers.get("SSL_CLIENT_S_DN", "")
    
    # 2. Comprobar verificación SSL exitosa 
    if verify != "SUCCESS":
        return """
        <html><body>
            <h1 style='color:red'>Error 403: Acceso Denegado</h1>
            <p>El certificado no ha sido verificado correctamente por el servidor.</p>
        </body></html>
        """, 403

    # 3. Comprobar identidad del Superusuario [cite: 50-51]
    # Se debe verificar que el CN sea exactamente "Superusuario"
    nombre_cn, _ = parse_dn(subject_dn)
    
    if nombre_cn != "Superusuario":
        # Si el usuario es "Piero" o cualquier otro, se le deniega el acceso
        return f"""
        <html><body>
            <h1 style='color:red'>Error 403: Prohibido</h1>
            <p>Hola <strong>{nombre_cn}</strong>. No tienes permisos para acceder a esta zona.</p>
            <p>Se requiere rol de <strong>Superusuario</strong>.</p>
            <p><a href="/">Volver al inicio</a></p>
        </body></html>
        """, 403

    # --- FIN LÓGICA DE SEGURIDAD BLOQUE 3 ---
    
    log_entries, error = read_user_log()
    
    # Ordenar por timestamp (Bloque 3.4) [cite: 70]
    if log_entries:
        log_entries.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Calcular estadísticas (Bloque 3.4) [cite: 68-69]
    total_accesos = len(log_entries)
    usuarios_distintos = len(set(entry['email'] for entry in log_entries))
    
    table_rows = ""
    for entry in log_entries:
        table_rows += f"""
        <tr>
            <td>{entry['fecha_hora']}</td>
            <td>{entry['nombre']}</td>
            <td>{entry['email']}</td>
            <td>{entry['ip']}</td>
        </tr>
        """
        
    if error:
        content = f"<p style='color: red; font-weight: bold;'>Error al cargar el log: {error}</p>"
    else:
        content = f"""
            <div class="stats-block">
                <p><strong>Total de Accesos:</strong> {total_accesos}</p>
                <p><strong>Usuarios Distintos:</strong> {usuarios_distintos}</p>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Fecha y Hora</th>
                        <th>Nombre</th>
                        <th>Email</th>
                        <th>IP</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        """

    html = f"""
    <html>
        <head>
            <title>Panel de Administración - PKI</title>
            <meta charset="utf-8" />
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f0f4f7; }}
                .container {{ background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }}
                h1 {{ color: #00796b; border-bottom: 2px solid #00bcd4; padding-bottom: 10px; }}
                .stats-block {{ 
                    background-color: #e8f5e9; 
                    padding: 15px; 
                    border-radius: 5px; 
                    margin-bottom: 20px; 
                    display: flex; 
                    justify-content: space-around;
                }}
                .stats-block p {{ margin: 0; font-size: 1.1em; }}
                table {{ 
                    width: 100%; 
                    border-collapse: collapse; 
                    margin-top: 20px; 
                    box-shadow: 0 0 5px rgba(0,0,0,0.05);
                }}
                th, td {{ 
                    border: 1px solid #cfd8dc; 
                    padding: 10px; 
                    text-align: left; 
                }}
                th {{ 
                    background-color: #00bcd4; 
                    color: white; 
                    font-weight: bold; 
                }}
                tr:nth-child(even) {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Panel de Administración - Accesos Autenticados</h1>
                <p>Bienvenido, <strong>{nombre_cn}</strong>.</p>
                {content}
                <p style="margin-top: 20px;"><a href="/">Volver a la página principal</a></p>
            </div>
        </body>
    </html>
    """
    return html

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)