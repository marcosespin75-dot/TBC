# sipcap

Analizador de capturas `.pcap` / `.pcapng` (también comprimidas con gzip) para resolver averías en enlaces SIP.
Solo necesita Python 3; no requiere tshark ni librerías externas.

## Uso

```
sipcap captura.pcap                  # resumen, averías agrupadas, llamadas, registros y OPTIONS
sipcap captura.pcap -l 44            # detalle y diagrama de flujo de la llamada nº 44
sipcap captura.pcap -l 44 -m         # igual, con el texto completo de cada mensaje SIP
sipcap captura.pcap -n 600123456     # solo llamadas en las que aparece ese número
sipcap captura.pcap -p               # solo llamadas con errores o avisos
sipcap captura.pcap -a               # incluye los intentos de escaneo/ataque en la lista
sipcap captura.pcap --html           # informe HTML (junto a la captura) y lo abre en el navegador
```

## Qué detecta

- **Llamadas:** estado final, códigos SIP explicados en español y causas Q.850 (cabecera Reason).
- **INVITE:** INVITE sin respuesta o retransmitidos, e INVITE desviados a destinos que no responden (registros caducados).
- **ACK:** ACK perdido o enviado a una dirección equivocada; llamadas cortadas a los ~32 s.
- **NAT:** IP privada en Contact/SDP enviada desde una IP pública.
- **Fallos de diálogo:** BYE sin respuesta, 481, re-INVITE rechazados y cortes por Session-Expires.
- **SDP:** códecs sin coincidencia, DTMF RFC 2833 no negociado, llamadas en espera.
- **Tamaño de los mensajes:** mensajes UDP grandes (riesgo de fragmentación) y fragmentos IP.
- **Audio (si la captura incluye RTP):** audio unidireccional, pérdida, jitter y huecos.
- **REGISTER:** credenciales rechazadas, 403, falta de respuesta y Contact tras NAT.
- **Extensiones sin registro:** periodos en que una extensión se queda sin ningún registro, porque el teléfono se da de baja (expires=0) o porque el registro caduca. Lista las llamadas que no le llegaron (480 "not registered").
- **Terminales:** respuestas de la centralita que no llegan al teléfono ("sorderas": el teléfono repite peticiones ya contestadas), tiempo de respuesta de cada teléfono comparado con el resto de su misma IP (si es mucho más lento, suele ser Wi-Fi o ahorro de energía), cortes de keepalive, ráfagas de REGISTER por detección de NAT y reconexiones a la Wi-Fi (si la captura incluye las tramas WPA/EAPOL).
- **OPTIONS:** keepalives sin respuesta, con los periodos de corte y el tiempo de respuesta.
- **Escaneos y fraude:** friendly-scanner, pplsip, User-Agent rotativos… Avisa si alguno llegó a ser contestado.

## Formatos soportados

- Ethernet (con VLAN), Linux cooked v1/v2 (captura en `any`), IP sin cabecera de enlace y loopback.
- IPv4 (reensambla fragmentos) e IPv6.
- SIP sobre UDP y TCP (con reensamblado). TLS (5061) no se puede descifrar.
