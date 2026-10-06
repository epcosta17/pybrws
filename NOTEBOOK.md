# Lab notebook

Una entrada por sesion. Formato: fecha / hipotesis / comando / resultado /
que aprendi. Este archivo **es** el blog post; no lo dejes para el final.

---

## 2026-10-06 — Arranque

**Hipotesis:** el ClientHello es un formato de 7 campos; puedo parsearlo y
re-emitirlo byte a byte sin implementar criptografia.

**Hecho:** andamio del proyecto. Tests en rojo que definen la API del parser.

**Pendiente:** escribir `parser.parse_client_hello`.

**Preguntas abiertas:**
- Mi Firefox, ¿manda GREASE? (responder con captura propia, no buscando)
- ¿El ClientHello de Firefox es estable entre conexiones o varia?
- Con PQ apagado, ¿cuantos bytes mide? ¿cabe en un paquete?
