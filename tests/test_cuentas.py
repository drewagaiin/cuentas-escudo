#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas de cuentas-escudo. Se corren con:  python3 -m unittest -v
No necesitan instalar nada ni usar la red."""
import importlib.util
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")
PROG = os.path.join(ROOT, "cuentas-escudo.py")

# Importar el módulo (el nombre tiene guion, así que se carga por ruta).
spec = importlib.util.spec_from_file_location("cuentas", PROG)
ce = importlib.util.module_from_spec(spec)
sys.modules["cuentas"] = ce          # necesario para dataclasses con anotaciones
spec.loader.exec_module(ce)


def run(args, stdin=None):
    """Ejecuta la herramienta como proceso. Devuelve (código, stdout, stderr)."""
    r = subprocess.run([sys.executable, PROG, *args], input=stdin,
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def fx(name):
    return os.path.join(FIX, name)


class Deteccion(unittest.TestCase):
    def test_bruteforce_success(self):
        c, out, _ = run([fx("m365_bruteforce.csv")])
        self.assertEqual(c, 3)
        self.assertIn("BRUTE-SUCCESS", out)
        self.assertIn("PELIGROSO", out)

    def test_legacy_success(self):
        c, out, _ = run([fx("m365_legacy.csv")])
        self.assertEqual(c, 3)
        self.assertIn("LEGACY-AUTH-SUCCESS", out)

    def test_spray_success(self):
        c, out, _ = run([fx("m365_spray.csv")])
        self.assertEqual(c, 3)
        self.assertIn("SPRAY-SUCCESS", out)

    def test_mfa_fatigue(self):
        c, out, _ = run([fx("m365_mfa.csv")])
        self.assertEqual(c, 3)
        self.assertIn("MFA-FATIGUE", out)

    def test_impossible_travel_json(self):
        c, out, _ = run([fx("m365_travel.json"), "--detalle"])
        self.assertEqual(c, 3)
        self.assertIn("IMPOSSIBLE-TRAVEL", out)
        self.assertIn("T1078", out)

    def test_google_suspicious(self):
        c, out, _ = run([fx("google_suspicious.csv")])
        self.assertEqual(c, 3)
        self.assertIn("PROVIDER-FLAGGED", out)

    def test_entra_json_legacy(self):
        c, out, _ = run([fx("m365_entra.json")])
        self.assertEqual(c, 3)
        self.assertIn("LEGACY-AUTH-SUCCESS", out)

    def test_limpio_sin_indicios(self):
        c, out, _ = run([fx("limpio.csv")])
        self.assertEqual(c, 0)
        self.assertIn("SIN INDICIOS", out)


class Formatos(unittest.TestCase):
    def test_stdin(self):
        with open(fx("m365_bruteforce.csv")) as fh:
            data = fh.read()
        c, out, _ = run(["-"], stdin=data)
        self.assertEqual(c, 3)
        self.assertIn("BRUTE-SUCCESS", out)

    def test_carpeta(self):
        c, out, _ = run([FIX])
        self.assertEqual(c, 3)   # la carpeta tiene casos peligrosos
        self.assertIn("cuentas-escudo", out)

    def test_json_lines_salida(self):
        c, out, _ = run([fx("m365_bruteforce.csv"), "--salida", "json"])
        self.assertEqual(c, 3)
        lineas = [ln for ln in out.splitlines() if ln.strip()]
        for ln in lineas:
            json.loads(ln)   # cada línea debe ser JSON válido
        resumen = json.loads(lineas[-1])
        self.assertEqual(resumen["type"], "summary")
        self.assertEqual(resumen["verdict_code"], 3)

    def test_jsonlines_entrada(self):
        obj = {"createdDateTime": "2026-10-01T08:00:00Z",
               "userPrincipalName": "x@e.com", "ipAddress": "1.2.3.4",
               "clientAppUsed": "IMAP4", "status": {"errorCode": 0},
               "location": {"countryOrRegion": "NL"}}
        data = "\n".join([json.dumps(obj)] * 2)
        c, out, _ = run(["-", "--formato", "jsonl"], stdin=data)
        self.assertEqual(c, 3)
        self.assertIn("LEGACY-AUTH", out)


class Seguridad(unittest.TestCase):
    def test_anonimizar(self):
        c, out, _ = run([fx("m365_bruteforce.csv"), "--anonimizar"])
        self.assertNotIn("ana.perez", out)
        self.assertIn("***@empresa.com.pa", out)

    def test_anonimizar_json(self):
        c, out, _ = run([fx("m365_bruteforce.csv"), "--anonimizar", "--salida", "json"])
        self.assertNotIn("ana.perez", out)

    def test_limpieza_control(self):
        # Un usuario con secuencia ANSI y salto de línea no debe alterar la salida.
        malo = ('Date (UTC),Username,IP address,Country,Client app,Sign-in error code\n'
                '2026-10-01T08:00:00Z,"\x1b[31mevil\nINYECTADO",1.2.3.4,NL,IMAP4,0\n'
                '2026-10-01T08:01:00Z,"\x1b[31mevil\nINYECTADO",1.2.3.4,NL,IMAP4,0\n')
        c, out, _ = run(["-"], stdin=malo)
        self.assertNotIn("\x1b[31m", out)
        self.assertNotIn("\nINYECTADO", out)

    def test_symlink_rechazado(self):
        import tempfile
        d = tempfile.mkdtemp()
        objetivo = os.path.join(d, "real.txt")
        enlace = os.path.join(d, "informe.txt")
        with open(objetivo, "w") as fh:
            fh.write("previo")
        try:
            os.symlink(objetivo, enlace)
        except OSError:
            self.skipTest("symlinks no soportados")
        c, out, err = run([fx("limpio.csv"), "-o", enlace])
        self.assertEqual(c, 2)
        with open(objetivo) as fh:
            self.assertEqual(fh.read(), "previo")  # no se sobrescribió

    def test_archivo_inexistente(self):
        c, out, err = run(["/no/existe/nada.csv"])
        self.assertEqual(c, 2)
        self.assertIn("Error", err)

    def test_no_es_registro(self):
        c, out, err = run(["-"], stdin="hola mundo esto no es un log\n")
        self.assertEqual(c, 2)


class Robustez(unittest.TestCase):
    def test_haversine_mismo_punto(self):
        self.assertAlmostEqual(ce.haversine_km(8.98, -79.52, 8.98, -79.52), 0.0, places=6)

    def test_haversine_conocido(self):
        # Panamá a Moscú ~ 10,800 km (tolerancia amplia)
        d = ce.haversine_km(8.98, -79.52, 55.75, 37.61)
        self.assertTrue(10000 < d < 11500, d)

    def test_parse_ts_variantes(self):
        for s in ("2026-10-01T08:00:00Z", "2026-10-01T08:00:00+00:00",
                  "2026-10-01 08:00:00", "10/01/2026 08:00:00"):
            self.assertIsNotNone(ce.parse_ts(s), s)
        self.assertIsNone(ce.parse_ts("no es fecha"))

    def test_umbral_invalido(self):
        c, out, err = run([fx("limpio.csv"), "--umbral-fallos", "0"])
        self.assertEqual(c, 2)

    def test_pais_invalido(self):
        c, out, err = run([fx("limpio.csv"), "--pais", "PANAMA"])
        self.assertEqual(c, 2)

    def test_dividir_por_cero_viaje(self):
        # Dos éxitos con la MISMA hora pero muy lejos: velocidad infinita, no debe reventar.
        datos = [
          {"createdDateTime":"2026-10-01T08:00:00Z","userPrincipalName":"z@e.com",
           "ipAddress":"1.1.1.1","clientAppUsed":"Browser","status":{"errorCode":0},
           "location":{"countryOrRegion":"PA","geoCoordinates":{"latitude":8.9,"longitude":-79.5}}},
          {"createdDateTime":"2026-10-01T08:00:00Z","userPrincipalName":"z@e.com",
           "ipAddress":"2.2.2.2","clientAppUsed":"Browser","status":{"errorCode":0},
           "location":{"countryOrRegion":"RU","geoCoordinates":{"latitude":55.7,"longitude":37.6}}},
        ]
        c, out, _ = run(["-", "--formato", "json"], stdin=json.dumps(datos))
        self.assertIn(c, (3,))
        self.assertIn("IMPOSSIBLE-TRAVEL", out)


class Regresiones(unittest.TestCase):
    """Casos que una revisión adversarial encontró y se corrigieron."""

    def test_json_actor_no_dict_no_revienta(self):
        for data in ('[{"actor":{"email":"a@b.com"},"events":["x"]}]',
                     '[{"actor":"nodict","events":[{"name":"login_success"}]}]'):
            c, out, err = run(["-", "--formato", "json"], stdin=data)
            self.assertIn(c, (0, 1, 2, 3), (data, err))
            self.assertNotIn("Traceback", err)

    def test_country_inyeccion_ansi(self):
        # País con ANSI + limpiar pantalla no debe llegar crudo a la salida.
        fila = '\x1b[31m\x1b[2JHACK'
        data = ("Date (UTC),Username,IP address,Country,Client app,Sign-in error code\n"
                f'2026-10-01T08:00:00Z,a@e.com,1.1.1.1,"{fila}",Browser,0\n'
                f'2026-10-01T08:10:00Z,a@e.com,2.2.2.2,"PA",Browser,0\n')
        c, out, _ = run(["-"], stdin=data)
        self.assertNotIn("\x1b[2J", out)
        self.assertNotIn("\x1b[31m", out)

    def test_columna_duplicada_usa_no_vacia(self):
        data = ("Date (UTC),Email,Username,IP address,Country,Client app,Sign-in error code\n"
                '2026-10-01T08:00:00Z,,real@e.com,1.1.1.1,NL,IMAP4,0\n'
                '2026-10-01T08:05:00Z,,real@e.com,1.1.1.1,NL,IMAP4,0\n')
        c, out, _ = run(["-"], stdin=data)
        self.assertIn("LEGACY-AUTH-SUCCESS", out)
        self.assertIn("real@e.com", out)

    def test_todo_extranjero(self):
        data = ("Date (UTC),Username,IP address,Country,Client app,Sign-in error code\n"
                '2026-10-01T08:00:00Z,b@e.com,1.1.1.1,RU,Browser,0\n'
                '2026-10-02T08:00:00Z,b@e.com,1.1.1.2,RU,Browser,0\n')
        c, out, _ = run(["-", "--pais", "PA"], stdin=data)
        self.assertEqual(c, 3)
        self.assertIn("ALL-FOREIGN", out)

    def test_bloqueo_ca_no_es_fuerza_bruta(self):
        # 12 bloqueos por acceso condicional (53003) NO deben ser BRUTE-FORCE.
        filas = "".join(
            f'2026-10-01T08:{i:02d}:00Z,c@e.com,1.1.1.1,PA,Browser,53003\n'
            for i in range(12))
        data = ("Date (UTC),Username,IP address,Country,Client app,Sign-in error code\n"
                + filas)
        c, out, _ = run(["-"], stdin=data)
        self.assertNotIn("BRUTE", out)

    def test_velocidad_nan_rechazada(self):
        c, out, err = run([fx("limpio.csv"), "--velocidad", "nan"])
        self.assertEqual(c, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
