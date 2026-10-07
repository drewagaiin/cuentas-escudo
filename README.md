# cuentas-escudo

Un día, el contador de una empresa entra a su correo como siempre. Lo que no sabe es que, tres días antes, alguien en otro país entró con su misma contraseña, leyó sus mensajes y preparó un fraude. Nadie se dio cuenta, porque un inicio de sesión robado no hace ruido: no hay virus, no hay ventana rota. Solo un acceso más en la lista.

**cuentas-escudo** lee esa lista de inicios de sesión —la que tu empresa puede exportar de Microsoft 365 o Google Workspace— y busca las señales de que a alguien le robaron la cuenta.

No se conecta a internet. No necesita acceso a las cuentas de nadie. Solo lee el archivo que le das.

## Qué busca

- **Protocolos viejos que se saltan el doble factor** (IMAP, POP, SMTP básico). Es la forma favorita de usar una clave robada sin que el MFA estorbe.
- **Fuerza bruta**: muchos intentos fallidos contra una cuenta, y si después hubo un acceso correcto.
- **Rociado de contraseñas (spray)**: una misma dirección probando una contraseña contra muchos usuarios.
- **Viaje imposible**: la misma cuenta entra desde Panamá y media hora después desde Moscú.
- **Fatiga de MFA**: bombardean a la persona con avisos de doble factor hasta que acepta uno sin querer.
- **Países nuevos**: accesos desde fuera de tu país, o peor, cuando *todos* los accesos son de afuera.
- Y lo que el propio Google ya marcó como sospechoso.

Cada señal lleva su técnica de [MITRE ATT&CK](https://attack.mitre.org/) (con `--detalle`), el marco que usan los equipos de seguridad en todo el mundo para nombrar los ataques.

## Cómo conseguir el archivo de registros

**Microsoft 365 (Entra ID):** en el centro de administración de Entra → *Monitoring* → *Sign-in logs* → *Download* (CSV o JSON).

**Google Workspace:** en la consola de administración → *Reporting* → *Audit* → *Login* → exportar a CSV (o a Hoja de cálculo y descargar como CSV).

## Cómo se usa

```bash
./cuentas-escudo.py registros.csv
./cuentas-escudo.py registros.json --detalle
./cuentas-escudo.py carpeta_de_logs/
cat registros.csv | ./cuentas-escudo.py -
```

Para equipos de seguridad:

```bash
./cuentas-escudo.py registros.csv --salida json        # una línea JSON por señal, para Wazuh/Splunk
./cuentas-escudo.py registros.csv --anonimizar          # oculta usuarios e IPs (Ley 81)
./cuentas-escudo.py registros.csv -o informe.txt        # guarda con permisos 600
./cuentas-escudo.py registros.csv --pais PA             # tu país (por defecto Panamá)
```

**Códigos de salida:** `0` sin indicios · `1` sospechoso · `3` peligroso · `2` error. Sirven para automatizar: *"si sale 3, avisa al equipo"*. Los umbrales (cuántos fallos, en cuánto tiempo) se ajustan con `--umbral-fallos`, `--ventana-fallos`, `--umbral-spray`, etc.

## Qué necesita

Solo **Python 3** (versión 3.9 o más nueva). Nada que instalar: usa únicamente la librería estándar. Kali, Debian y Ubuntu ya lo traen.

## Lo que NO hace

- No se conecta a las cuentas ni a internet. Tú le das el archivo exportado.
- No bloquea ni cierra cuentas. Señala y recomienda; una persona decide.
- No ve lo que no está en el registro. Un robo hecho con cuidado (desde el mismo país, con doble factor ya saltado) puede no dejar rastro aquí. Por eso dice "sin indicios claros", nunca "seguro".
- No reemplaza las alertas de Microsoft o Google; es una segunda mirada, con reglas que tú controlas y en español.

## Cómo se ha probado

30 pruebas automáticas (`python3 -m unittest discover -s tests`) con registros de ejemplo de Microsoft 365 y Google, sin usar la red. Antes de publicarlo pedí a un revisor de IA independiente que lo auditara como atacante: buscando a la vez formas de que un robo real se le escape y formas de romper la herramienta con un registro malicioso. Encontró cinco fallos (desde un cuelgue con JSON preparado hasta un bloqueo normal confundido con fuerza bruta); todos están corregidos y convertidos en prueba. El [CHANGELOG](CHANGELOG.md) los cuenta.

## Para estudiarlo

[docs/DETECCIONES.md](docs/DETECCIONES.md) explica cada señal con su nivel y su técnica de MITRE.

## Privacidad

Los registros contienen datos personales (nombres, correos, IPs). Analiza solo los de tu empresa o con permiso, usa `--anonimizar` para compartir informes, y no subas registros reales a GitHub. El `.gitignore` ya excluye las carpetas de datos.

## Parte de un kit

Junto con [ssh-sentinel](https://github.com/drewagaiin/ssh-sentinel) (accesos SSH), [correo-escudo](https://github.com/drewagaiin/correo-escudo) (correo) y [linux-audit](https://github.com/drewagaiin/linux-audit) (servidores), cubre las puertas por donde más entran los ataques a una pyme.

Licencia [MIT](LICENSE). Hecho por Andrés Clark en Panamá.
