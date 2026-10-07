# Seguridad

## Si encontraste un fallo

Si das con un registro que engaña a la herramienta (deja pasar un robo evidente, la cuelga, o hace que muestre algo en la terminal que no debería), avísame por **Security → Report a vulnerability** en GitHub. Queda privado hasta que esté arreglado. Contesto en una semana como mucho.

Si puedes, manda el archivo mínimo que lo provoca, con los datos reales borrados o cambiados. No los necesito.

Un falso positivo (un acceso normal marcado como sospechoso) no es una vulnerabilidad: ábrelo como issue normal.

## Lo que la herramienta promete

- **No toca nada ni se conecta.** Solo lee el archivo que le das. No abre enlaces, no contacta a Microsoft ni a Google, no modifica cuentas.
- **Trata el registro como entrada hostil.** Un atacante podría poner secuencias de escape o saltos de línea en un nombre de usuario, una IP o un país para ensuciar tu terminal o inyectar líneas falsas en el informe. Todo lo que viene del registro se limpia antes de mostrarse.
- **No se cuelga con archivos preparados.** Un JSON con formas raras, una fecha ilegible o un registro gigante no tumban el programa: se saltan o terminan con un error claro (código 2), no con un error de Python.
- **Falla de forma segura.** Si no entiende una fecha, ese evento no entra en las reglas por tiempo, pero se avisa; nunca inventa un veredicto.
- **Tus informes son tuyos.** Con `-o` se guardan con permisos 600 y no se siguen enlaces simbólicos, para que nadie engañe al programa y le haga escribir donde no debe.
- **Anonimiza si lo pides.** `--anonimizar` oculta usuarios e IPs para compartir el informe sin exponer datos personales (Ley 81 de Panamá).

## Lo que no promete

No es un antivirus ni reemplaza las protecciones de Microsoft o Google. Mira señales en un registro; un robo bien hecho puede no dejar rastro. Por eso el informe dice "sin indicios claros", nunca "es seguro".
