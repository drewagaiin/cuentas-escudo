# Qué detecta cuentas-escudo

Cada inicio de sesión del registro se convierte en un "evento" con: fecha, usuario, IP, país/ciudad (y coordenadas si vienen), estado (correcto, fallido, interrumpido por MFA, bloqueado) y el cliente/protocolo usado. Sobre esos eventos corren estas reglas.

| Código | Nivel | Qué significa | MITRE |
|---|---|---|---|
| `LEGACY-AUTH-SUCCESS` | Crítico | Inició sesión con un protocolo viejo (IMAP, POP, SMTP básico, ActiveSync) que no pide doble factor. La forma típica de usar una clave robada saltándose el MFA. | T1078.004 |
| `LEGACY-AUTH-ATTEMPT` | Medio | Hubo intentos con protocolos viejos, aunque no entraron. Conviene bloquear la autenticación heredada. | T1078.004 |
| `BRUTE-SUCCESS` | Crítico | Muchos intentos fallidos seguidos y luego un acceso correcto. Posible contraseña adivinada. | T1110.001 |
| `BRUTE-FORCE` | Alto | Muchos intentos fallidos contra una cuenta en poco tiempo. | T1110.001 |
| `SPRAY-SUCCESS` | Crítico | Una IP probó contraseñas contra muchos usuarios y al menos uno entró. | T1110.003 |
| `PASSWORD-SPRAY` | Alto | Una IP intentó entrar a muchos usuarios distintos en poco tiempo. | T1110.003 |
| `IMPOSSIBLE-TRAVEL` | Alto | Dos accesos correctos a tanta distancia que es imposible viajar entre ellos en ese tiempo. Usa las coordenadas del registro. | T1078 |
| `FAST-COUNTRY-CHANGE` | Medio | Dos accesos correctos desde países distintos en menos de una hora (sin coordenadas para medir distancia). Puede ser VPN. | T1078 |
| `MFA-FATIGUE` | Alto | Varios rechazos o no-respuestas de doble factor seguidos y después un acceso correcto. Bombardeo de avisos hasta que la persona acepta uno. | T1621 |
| `ALL-FOREIGN` | Alto | Todos los accesos correctos son desde fuera de tu país. | T1078 |
| `NEW-COUNTRY` | Medio | Hay accesos desde fuera de tu país, además de los locales. | T1078 |
| `PROVIDER-FLAGGED` | Alto | El propio Google marcó el inicio de sesión como sospechoso. | T1078 |

## Cómo decide el veredicto

- **PELIGROSO** (código de salida 3): hay al menos una señal de nivel alto o crítico.
- **SOSPECHOSO** (código 1): solo señales de nivel medio o bajo.
- **SIN INDICIOS CLAROS** (código 0): ninguna regla saltó. No es una garantía de que todo esté bien.

## Qué NO cuenta como ataque

- Un bloqueo por acceso condicional (error 53003) o un bloqueo de cuenta (50053) **no** se cuenta como fuerza bruta: no es alguien adivinando la clave.
- Una simple solicitud de doble factor (error 50074) **no** cuenta como fatiga de MFA. La fatiga se basa en rechazos repetidos (500121).
- Los clientes modernos ("Browser", "Mobile Apps and Desktop clients") **no** se marcan como protocolo heredado.

## Umbrales por defecto (ajustables)

| Qué | Valor | Cómo cambiarlo |
|---|---|---|
| Fallos para fuerza bruta | 10 en 10 min | `--umbral-fallos`, `--ventana-fallos` |
| Usuarios para spray | 5 en 60 min | `--umbral-spray`, `--ventana-spray` |
| Rechazos de MFA para fatiga | 5 | `--umbral-mfa` |
| Velocidad imposible | 900 km/h | `--velocidad` |
| País propio | PA | `--pais` |
