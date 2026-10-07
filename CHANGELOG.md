# Cambios

## [1.0.0] - 2026-10-07

Primera versión.

- Lee registros de inicio de sesión de Microsoft 365 (Entra ID) y Google Workspace, en CSV, JSON o JSON Lines, sin usar internet.
- Detecta: autenticación heredada sin MFA, fuerza bruta (y con éxito), rociado de contraseñas (spray), viaje imposible, fatiga de MFA, países nuevos y accesos marcados por el proveedor. Cada señal con su técnica de MITRE ATT&CK.
- Salida en texto o JSON Lines para un SIEM (Wazuh, Splunk). Códigos de salida para automatizar. `--anonimizar` para la Ley 81. Informes con permisos 600.

### Revisión de seguridad antes de publicar (5 fallos corregidos)
Un revisor de IA independiente auditó la herramienta como atacante. Encontró y se corrigió:
- Un JSON preparado (con `actor` o `events` de un tipo inesperado) colgaba el programa con un error de Python. Ahora se salta el registro malo.
- El país del registro llegaba sin limpiar a la salida: permitía meter secuencias de escape en la terminal. Ahora se limpia como el resto.
- Si dos columnas del CSV apuntaban al mismo dato (por ejemplo "Email" y "Username") y la primera venía vacía, se perdía el usuario real y no se detectaba nada. Ahora se usa el primer valor no vacío.
- Una cuenta usada SOLO desde el extranjero no se marcaba. Ahora sale como `ALL-FOREIGN` (alto).
- Un bloqueo por política (acceso condicional) o un bloqueo de cuenta se contaban como fuerza bruta. Ahora se excluyen: no son intentos de adivinar la clave.

También se afinó la fatiga de MFA para que no salte con solicitudes normales de doble factor, y el viaje imposible para que un acceso sin coordenadas en medio no tape uno real.
