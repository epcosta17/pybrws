# pybrws

Un cliente HTTPS en Python que emite un ClientHello **byte-idéntico** al de un
navegador real, escrito desde cero.

## Regla del proyecto: clean room

Reconstruyo el problema sin leer a quien ya lo resolvio.

**Prohibido:** `curl-impersonate`, `uTLS`, `curl_cffi`, `tls-client`, `camoufox`,
y cualquier writeup que explique como parchearon. Se abren **al final**, para la
seccion de comparacion.

**Permitido y obligatorio:** mis propias capturas, los RFCs (8446, 8701, 7540),
`tls13.xargs.org`, y el codigo fuente de NSS / Firefox / OpenSSL. Leer el
original no es leer la copia.

## Criterio de "terminado"

Tres barras. Declarar explicitamente cual se alcanzo.

- [ ] **Bronce** — JA4 identico al de Firefox real
- [ ] **Plata** — ClientHello byte-identico (salvo `random` y `key_share`, que por
      definicion varian)
- [ ] **Oro** — byte-identico + fingerprint HTTP/2 identico + orden de headers
      identico, verificado contra `tls.peet.ws/api/all`

## Scope v1

- Objetivo: **Firefox con key agreement post-cuantico deshabilitado**
  (`about:config`). Soportar `X25519MLKEM768` es trabajo futuro: ver NOTEBOOK.
- **No se verifica el certificado.** Esto es un laboratorio, no un cliente
  seguro. No usar para nada real.
- Sin renegociacion ni reanudacion de sesion en v1.

## Fases

| Fase | Que | Estado |
|------|-----|--------|
| 0 | Oraculo: parser + differ de ClientHello | en curso |
| 1 | Golden file: capturar Firefox real | pendiente |
| 2 | Emisor: generar bytes hasta que el diff cierre | pendiente |
| 3 | Handshake completo (`cryptography` para primitivas) | pendiente |
| 4 | HTTP/2: frames, SETTINGS, orden de headers (`h2`) | pendiente |
| 5 | CLI con sabor a curl | pendiente |
| 6 | Sidecar proxy CONNECT (consumible desde Ruby/Node) | pendiente |

**Fases 0-2 no necesitan dependencias.** Solo stdlib.
La Fase 3 pedira `cryptography`; la Fase 4, `h2`.

## El loop

    capturar  ->  computar  ->  mutar  ->  verificar  ->  explicar la diferencia

La profundidad no viene de que el hash coincida. Viene de poder explicar **por
que** un campo difiere y si esa diferencia es detectable.

## Uso

Capturar un ClientHello (sin Wireshark, ver `fixtures/README.md`):

    python tools/catch_hello.py fixtures/firefox.hex

Correr los tests:

    python -m unittest discover -s tests -t . -v
