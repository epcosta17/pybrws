# fixtures

Golden files: ClientHellos crudos, en hex. No se versionan (ver .gitignore):
son tuyos y de tu maquina.

## La trampa del SNI (leela antes de capturar)

Si apuntas el navegador a `https://127.0.0.1:4443`, **no manda la extension
`server_name`**: el SNI solo existe para hostnames, no para IPs. Tu golden file
saldria sin SNI y no se pareceria a una conexion real. Peor: el JA4 lleva un
campo `d`/`i` que codifica justo eso, asi que tu fingerprint estaria mal desde
el primer caracter.

Arreglo: dale un nombre al loopback. Agrega a tu archivo hosts

    127.0.0.1   pybrws.test

- macOS / Linux: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts` (como administrador)

Y captura siempre contra `https://pybrws.test:4443`.

## Capturar

Terminal 1:

    python tools/catch_hello.py fixtures/firefox.hex --peek

Terminal 2 (o el navegador): abre `https://pybrws.test:4443`.
Va a fallar el handshake y a mostrar un error. Da igual: el ClientHello ya salio.

## Que capturar

| Archivo | Como |
|---|---|
| `firefox.hex` | Firefox, PQ **apagado** en about:config. Tu objetivo v1. |
| `firefox-pq.hex` | Firefox con PQ encendido. Para comparar tamanos. |
| `chrome.hex` | Chrome. Para ver que extensiones lo distinguen. |
| `python-ssl.hex` | `python -c "import ssl,socket; ssl.create_default_context().wrap_socket(socket.create_connection(('pybrws.test',4443)), server_hostname='pybrws.test')"` |
| `curl.hex` | `curl https://pybrws.test:4443` |

## Captura Firefox cinco veces seguidas

Guardalas como `firefox-1.hex` .. `firefox-5.hex` y diffealas entre si.

**¿Es estable el ClientHello de Firefox, o varia?** Si varia, ¿que parte? Eso
cambia la definicion de "correcto" para todo el proyecto. Responde esto antes
de escribir una sola linea del emisor, y anota la respuesta en NOTEBOOK.md.
