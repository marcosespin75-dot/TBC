#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sipcap — Analizador de capturas .pcap/.pcapng para resolver averías en enlaces SIP.

Uso:
  sipcap captura.pcap                   Resumen, llamadas y problemas detectados
  sipcap captura.pcap -l 3              Detalle y diagrama de la llamada nº 3
  sipcap captura.pcap -l 3 -m           Igual, mostrando el texto completo de cada mensaje
  sipcap captura.pcap -n 600123456      Solo llamadas en las que aparece ese número
  sipcap captura.pcap -p                Solo llamadas con errores o avisos
  sipcap captura.pcap -a                Incluye también los intentos de escaneo/ataque
  sipcap captura.pcap --html            Informe HTML completo (se abre en el navegador)

Lee pcap y pcapng (también comprimidos con gzip). Sin dependencias: solo Python 3.8+.
"""
import argparse
import gzip
import html
import ipaddress
import os
import re
import socket
import struct
import sys
import webbrowser
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime

# ───────────────────────────── Tablas de referencia ─────────────────────────────

CODIGOS = {
    400: 'Petición mal formada: el otro extremo no entiende el mensaje (cabeceras o formato de número incorrectos).',
    401: 'Requiere autenticación (normal si después se reintenta con credenciales).',
    402: 'Pago requerido: saldo agotado o servicio no contratado en el proveedor.',
    403: 'Prohibido: credenciales incorrectas, IP no autorizada en el proveedor o número de origen/destino no permitido.',
    404: 'No encontrado: número mal marcado, formato incorrecto (prefijo 0034/+34) o extensión inexistente.',
    405: 'Método no permitido por el otro extremo.',
    407: 'Requiere autenticación de proxy (normal si después se reintenta con credenciales).',
    408: 'Tiempo agotado: el destino no respondió a tiempo.',
    410: 'El número ya no existe.',
    412: 'Petición condicional fallida (habitual en PUBLISH de presencia, normalmente inofensivo).',
    413: 'Mensaje demasiado grande.',
    414: 'URI demasiado larga.',
    415: 'Tipo de contenido no soportado.',
    416: 'Esquema de URI no soportado.',
    420: 'Extensión no soportada (cabecera Require).',
    421: 'Se requiere una extensión que no se ha indicado.',
    422: 'Session-Expires demasiado bajo.',
    423: 'Intervalo de registro demasiado corto.',
    480: 'Temporalmente no disponible: destino no registrado, desconectado o en No Molestar.',
    481: 'El diálogo o la transacción no existe: desajuste de estado (a menudo por NAT o por un BYE/ACK que va al sitio equivocado).',
    482: 'Bucle detectado.',
    483: 'Demasiados saltos (bucle de enrutamiento).',
    484: 'Número incompleto.',
    485: 'Destino ambiguo.',
    486: 'Ocupado.',
    487: 'Petición cancelada (el llamante colgó antes de que contestaran).',
    488: 'No aceptable: no hay códec en común o el SDP fue rechazado.',
    489: 'Evento no soportado.',
    491: 'Petición pendiente (re-INVITE cruzados).',
    493: 'No descifrable.',
    500: 'Error interno del servidor.',
    501: 'No implementado.',
    502: 'Bad Gateway: fallo en un salto posterior.',
    503: 'Servicio no disponible: troncal caído, sin canales, sobrecarga o sin ruta de salida.',
    504: 'Timeout de pasarela: un salto posterior no respondió.',
    505: 'Versión SIP no soportada.',
    513: 'Mensaje demasiado grande (posible problema de fragmentación UDP; probar con TCP).',
    580: 'Precondición fallida.',
    600: 'Ocupado en todas partes.',
    603: 'Rechazada por el destino.',
    604: 'El destino no existe en ninguna parte.',
    606: 'No aceptable.',
}

Q850 = {
    1: 'número no asignado', 2: 'sin ruta a la red', 3: 'sin ruta al destino', 6: 'canal inaceptable',
    16: 'liberación normal', 17: 'usuario ocupado', 18: 'el usuario no responde', 19: 'sin respuesta (timbra y no contesta)',
    20: 'abonado ausente', 21: 'llamada rechazada', 22: 'número cambiado', 26: 'liberación de usuario no seleccionado',
    27: 'destino fuera de servicio', 28: 'formato de número inválido', 29: 'facilidad rechazada',
    31: 'normal, sin especificar', 34: 'no hay circuito/canal disponible', 38: 'red fuera de servicio',
    41: 'fallo temporal', 42: 'congestión del equipo de conmutación', 44: 'canal solicitado no disponible',
    47: 'recurso no disponible', 50: 'facilidad no suscrita', 55: 'llamadas entrantes restringidas',
    57: 'capacidad portadora no autorizada', 58: 'capacidad portadora no disponible',
    63: 'servicio no disponible', 65: 'capacidad portadora no implementada', 69: 'facilidad no implementada',
    79: 'servicio no implementado', 87: 'usuario no miembro del grupo cerrado', 88: 'destino incompatible',
    95: 'mensaje inválido', 96: 'falta un elemento obligatorio', 97: 'tipo de mensaje inexistente',
    100: 'contenido de elemento inválido', 102: 'expiración de temporizador', 111: 'error de protocolo',
    127: 'interfuncionamiento, sin especificar',
}

PT_ESTATICOS = {
    '0': ('PCMU', 8000), '3': ('GSM', 8000), '4': ('G723', 8000), '8': ('PCMA', 8000),
    '9': ('G722', 8000), '13': ('CN', 8000), '18': ('G729', 8000),
}

COMPACTAS = {
    'i': 'call-id', 'm': 'contact', 'e': 'content-encoding', 'l': 'content-length', 'c': 'content-type',
    'f': 'from', 's': 'subject', 'k': 'supported', 't': 'to', 'v': 'via', 'o': 'event',
    'r': 'refer-to', 'b': 'referred-by', 'x': 'session-expires', 'u': 'allow-events',
}

NIVELES = ['ok', 'info', 'aviso', 'error']
NO_AUDIO = ('TELEPHONE-EVENT', 'CN', 'COMFORT-NOISE')
CGNAT = ipaddress.ip_network('100.64.0.0/10')

# ───────────────────────────── Lectura de capturas ─────────────────────────────

PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}


def abrir(path):
    with open(path, 'rb') as f:
        cab = f.read(2)
    return gzip.open(path, 'rb') if cab == b'\x1f\x8b' else open(path, 'rb')


def leer_paquetes(path):
    """Genera (timestamp, linktype, datos) para cada paquete."""
    with abrir(path) as f:
        magic = f.read(4)
        if magic in PCAP_MAGICS:
            yield from _leer_pcap(f, *PCAP_MAGICS[magic])
        elif magic == b'\x0a\x0d\x0d\x0a':
            yield from _leer_pcapng(f)
        else:
            raise ValueError('formato no reconocido (no es pcap ni pcapng)')


def _leer_pcap(f, e, res):
    cab = f.read(20)
    if len(cab) < 20:
        return
    linktype = struct.unpack(e + 'I', cab[16:20])[0] & 0xFFFF
    reg = struct.Struct(e + 'IIII')
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        seg, frac, incl, _ = reg.unpack(h)
        datos = f.read(incl)
        if len(datos) < incl:
            return
        yield seg + frac * res, linktype, datos


def _leer_pcapng(f):
    e = '<'
    ifaces = []
    ultimo_ts = 0.0
    tipo_raw = b'\x0a\x0d\x0d\x0a'
    primero = True
    while True:
        if not primero:
            tipo_raw = f.read(4)
            if len(tipo_raw) < 4:
                return
        primero = False
        if tipo_raw == b'\x0a\x0d\x0d\x0a':          # Section Header Block
            len_raw, bom = f.read(4), f.read(4)
            if len(bom) < 4:
                return
            e = '<' if bom == b'\x4d\x3c\x2b\x1a' else '>'
            blen = struct.unpack(e + 'I', len_raw)[0]
            f.read(blen - 12)
            ifaces = []
            continue
        len_raw = f.read(4)
        if len(len_raw) < 4:
            return
        tipo = struct.unpack(e + 'I', tipo_raw)[0]
        blen = struct.unpack(e + 'I', len_raw)[0]
        if blen < 12:
            return
        resto = f.read(blen - 8)
        if len(resto) < blen - 8:
            return
        cuerpo = resto[:-4]
        if tipo == 1:                                   # Interface Description Block
            lt = struct.unpack(e + 'H', cuerpo[0:2])[0]
            res = 1e-6
            i = 8
            while i + 4 <= len(cuerpo):
                cod, ln = struct.unpack(e + 'HH', cuerpo[i:i + 4])
                if cod == 0:
                    break
                if cod == 9 and ln >= 1:
                    v = cuerpo[i + 4]
                    res = 2 ** -(v & 0x7f) if v & 0x80 else 10 ** -v
                i += 4 + ((ln + 3) & ~3)
            ifaces.append((lt, res))
        elif tipo == 6 and len(cuerpo) >= 20:           # Enhanced Packet Block
            iid, tsh, tsl, cap, _ = struct.unpack(e + 'IIIII', cuerpo[:20])
            if iid < len(ifaces):
                lt, res = ifaces[iid]
                ultimo_ts = ((tsh << 32) | tsl) * res
                yield ultimo_ts, lt, cuerpo[20:20 + cap]
        elif tipo == 3 and len(cuerpo) >= 4 and ifaces:  # Simple Packet Block
            yield ultimo_ts, ifaces[0][0], cuerpo[4:]
        elif tipo == 2 and len(cuerpo) >= 20:           # Packet Block (obsoleto)
            iid, _, tsh, tsl, cap, _ = struct.unpack(e + 'HHIIII', cuerpo[:20])
            if iid < len(ifaces):
                lt, res = ifaces[iid]
                ultimo_ts = ((tsh << 32) | tsl) * res
                yield ultimo_ts, lt, cuerpo[20:20 + cap]


def enlace(lt, d):
    """Quita la capa de enlace. Devuelve (ethertype, carga) o None."""
    if lt == 1:                                         # Ethernet
        if len(d) < 14:
            return None
        et = struct.unpack('!H', d[12:14])[0]
        off = 14
        while et in (0x8100, 0x88a8, 0x9100) and len(d) >= off + 4:
            et = struct.unpack('!H', d[off + 2:off + 4])[0]
            off += 4
        return et, d[off:]
    if lt == 113 and len(d) >= 16:                      # Linux cooked v1
        return struct.unpack('!H', d[14:16])[0], d[16:]
    if lt == 276 and len(d) >= 20:                      # Linux cooked v2
        return struct.unpack('!H', d[0:2])[0], d[20:]
    if lt in (101, 12, 14) and d:                       # IP sin cabecera de enlace
        return (0x0800 if d[0] >> 4 == 4 else 0x86dd), d
    if lt == 228:
        return 0x0800, d
    if lt == 229:
        return 0x86dd, d
    if lt in (0, 108) and len(d) > 4:                   # loopback BSD
        return (0x0800 if d[4] >> 4 == 4 else 0x86dd), d[4:]
    return None


def decodificar_ip(et, p, frags):
    """Devuelve (src, dst, proto, carga, fragmentado) o None. Reensambla fragmentos IPv4."""
    if et == 0x0800 and len(p) >= 20:
        ihl = (p[0] & 0xf) * 4
        tot = struct.unpack('!H', p[2:4])[0]
        if tot < ihl or tot > len(p):
            tot = len(p)
        ff = struct.unpack('!H', p[6:8])[0]
        mf, off = ff & 0x2000, (ff & 0x1fff) * 8
        proto = p[9]
        src, dst = socket.inet_ntoa(p[12:16]), socket.inet_ntoa(p[16:20])
        carga = p[ihl:tot]
        if mf or off:
            clave = (src, dst, p[4:6], proto)
            fr = frags.setdefault(clave, {'partes': {}, 'fin': None})
            fr['partes'][off] = carga
            if not mf:
                fr['fin'] = off + len(carga)
            if fr['fin'] is None:
                return None
            pos, trozos = 0, []
            for o in sorted(fr['partes']):
                if o > pos:
                    return None
                trozos.append(fr['partes'][o][pos - o:])
                pos = max(pos, o + len(fr['partes'][o]))
            if pos < fr['fin']:
                return None
            del frags[clave]
            return src, dst, proto, b''.join(trozos), True
        return src, dst, proto, carga, False
    if et == 0x86dd and len(p) >= 40:
        nh = p[6]
        plen = struct.unpack('!H', p[4:6])[0]
        src = socket.inet_ntop(socket.AF_INET6, p[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
        off = 40
        while nh in (0, 43, 60, 44):
            if nh == 44 or off + 2 > len(p):
                return None
            nh, off = p[off], off + (p[off + 1] + 1) * 8
        return src, dst, nh, p[off:40 + plen], False
    return None

# ───────────────────────────── SIP y SDP ─────────────────────────────

RE_REQ = re.compile(r'^([A-Za-z]+) (\S+) SIP/2\.0$')
RE_RES = re.compile(r'^SIP/2\.0 (\d{3}) ?(.*)$')
RE_INICIO_TCP = re.compile(rb'(?m)^(?:[A-Z]+ \S+ SIP/2\.0|SIP/2\.0 \d{3})')
RE_CL = re.compile(rb'(?im)^(?:content-length|l)[ \t]*:[ \t]*(\d+)')


def es_sip(d):
    if d.startswith(b'SIP/2.0 '):
        return True
    nl = d.find(b'\n', 0, 512)
    return nl > 0 and d[:1].isupper() and d[:nl].rstrip(b'\r').endswith(b' SIP/2.0')


def uri_usuario(v):
    m = re.search(r'(?:sips?|tel):([^@;>?\s]+)', v or '', re.I)
    return m.group(1) if m else (v or '')


def uri_host(v):
    m = re.search(r'sips?:(?:[^@;>\s]+@)?(\[[^\]]+\]|[^;>?:\s]+)', v or '', re.I)
    return m.group(1).strip('[]') if m else ''


def nombre_visible(v):
    m = re.match(r'\s*"([^"]*)"', v or '') or re.match(r'\s*([^<"]+?)\s*<', v or '')
    return m.group(1).strip() if m else ''


def es_privada(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private and not a.is_loopback and not a.is_unspecified) or (a.version == 4 and a in CGNAT)


def es_publica(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Sip:
    """Un mensaje SIP ya decodificado."""

    def __init__(self, raw, ts, src, sport, dst, dport, transporte, num, frag):
        self.raw, self.ts, self.num, self.frag = raw, ts, num, frag
        self.src, self.sport, self.dst, self.dport, self.transporte = src, sport, dst, dport, transporte
        self.ep_src, self.ep_dst = f'{src}:{sport}', f'{dst}:{dport}'
        self.retrans = False
        fin = raw.find(b'\r\n\r\n')
        sep = 4
        if fin < 0:
            fin, sep = raw.find(b'\n\n'), 2
        cab, cuerpo = (raw, b'') if fin < 0 else (raw[:fin], raw[fin + sep:])
        lineas = re.split(r'\r?\n', cab.decode('utf-8', 'replace'))
        self.primera = lineas[0].strip()
        m = RE_REQ.match(self.primera)
        if m:
            self.req, self.metodo, self.uri, self.codigo, self.motivo = True, m.group(1).upper(), m.group(2), 0, ''
        else:
            m = RE_RES.match(self.primera)
            if not m:
                raise ValueError('no es SIP')
            self.req, self.metodo, self.uri = False, '', ''
            self.codigo, self.motivo = int(m.group(1)), m.group(2).strip()
        self.cabeceras = []
        for ln in lineas[1:]:
            if ln[:1] in (' ', '\t') and self.cabeceras:
                k, v = self.cabeceras[-1]
                self.cabeceras[-1] = (k, v + ' ' + ln.strip())
                continue
            if ':' not in ln:
                continue
            k, v = ln.split(':', 1)
            k = k.strip().lower()
            self.cabeceras.append((COMPACTAS.get(k, k), v.strip()))
        self.cuerpo = cuerpo.decode('utf-8', 'replace')
        self.call_id = self.h('call-id')
        cs = self.h('cseq').split()
        self.cseq = int(cs[0]) if cs and cs[0].isdigit() else 0
        self.cseq_metodo = cs[1].upper() if len(cs) > 1 else ''
        self.to_tag = self._tag(self.h('to'))
        self.from_tag = self._tag(self.h('from'))
        b = re.search(r'branch=([^;,\s]+)', self.h('via'), re.I)
        self.branch = b.group(1) if b else ''
        self.sdp = parse_sdp(self.cuerpo) if 'sdp' in self.h('content-type').lower() else None

    @staticmethod
    def _tag(v):
        m = re.search(r';\s*tag=([^;>\s]+)', v, re.I)
        return m.group(1) if m else ''

    def h(self, nombre, defecto=''):
        for k, v in self.cabeceras:
            if k == nombre:
                return v
        return defecto

    def etiqueta(self):
        t = self.metodo if self.req else f'{self.codigo} {self.motivo}'
        if self.sdp:
            t += ' (SDP)'
        if self.retrans:
            t += ' [retx]'
        return t

    def texto(self):
        return self.raw.decode('utf-8', 'replace').replace('\r\n', '\n')


def parse_sdp(cuerpo):
    if 'm=' not in cuerpo:
        return None
    sesion = {'ip': None, 'rtpmap': {}, 'dir': 'sendrecv'}
    medias, cur = [], None
    for ln in cuerpo.splitlines():
        ln = ln.strip()
        if len(ln) < 2 or ln[1] != '=':
            continue
        k, v = ln[0], ln[2:]
        obj = cur if cur is not None else sesion
        if k == 'c':
            obj['ip'] = v.split()[-1].split('/')[0] if v.split() else None
        elif k == 'm':
            p = v.split()
            cur = {'tipo': p[0] if p else '', 'puerto': int(p[1].split('/')[0]) if len(p) > 1 and p[1].split('/')[0].isdigit() else 0,
                   'pts': p[3:], 'ip': None, 'rtpmap': {}, 'dir': None}
            medias.append(cur)
        elif k == 'a':
            if v.lower().startswith('rtpmap:'):
                try:
                    pt, resto = v[7:].split(None, 1)
                    partes = resto.split('/')
                    obj['rtpmap'][pt] = (partes[0].upper(), int(partes[1]) if len(partes) > 1 and partes[1].isdigit() else 8000)
                except ValueError:
                    pass
            elif v in ('sendrecv', 'sendonly', 'recvonly', 'inactive'):
                obj['dir'] = v
    for m in medias:
        m['ip'] = m['ip'] or sesion['ip']
        m['dir'] = m['dir'] or sesion['dir']
        m['codecs'] = [(m['rtpmap'].get(pt) or sesion['rtpmap'].get(pt) or PT_ESTATICOS.get(pt) or (f'PT{pt}', 8000))[0] for pt in m['pts']]
    return {'ip': sesion['ip'], 'medias': medias}


def audio(sdp):
    return next((m for m in sdp['medias'] if m['tipo'] == 'audio'), None) if sdp else None

# ───────────────────────────── Carga de la captura ─────────────────────────────


class Captura:
    def __init__(self, path):
        self.path = path
        self.sip = []
        self.rtp_crudo = defaultdict(list)
        self.tcp = {}
        self.frags = {}
        self.n = 0
        self.t0 = self.t1 = None
        self.tls = 0
        self.no_decod = 0
        self.eapol = []          # (ts, mac del equipo) — reconexiones Wi-Fi (handshake WPA)
        self.mac_de_ip = {}
        self._cargar()
        self._marcar_retransmisiones()

    def _cargar(self):
        for ts, lt, datos in leer_paquetes(self.path):
            self.n += 1
            if ts:
                if self.t0 is None:
                    self.t0 = ts
                self.t1 = ts
            if lt == 1 and len(datos) >= 34:
                et = datos[12:14]
                if et == b'\x88\x8e':
                    self.eapol.append((ts, datos[0:6], datos[6:12]))
                elif et == b'\x08\x00':
                    self.mac_de_ip.setdefault(socket.inet_ntoa(datos[26:30]), datos[6:12])
            r = enlace(lt, datos)
            if r is None:
                self.no_decod += 1
                continue
            ip = decodificar_ip(r[0], r[1], self.frags)
            if ip is None:
                continue
            src, dst, proto, pl, frag = ip
            if proto == 17 and len(pl) >= 8:
                sport, dport, ulen = struct.unpack('!HHH', pl[:6])
                self._udp(ts, src, sport, dst, dport, pl[8:ulen] if 8 <= ulen <= len(pl) else pl[8:], frag)
            elif proto == 6 and len(pl) >= 20:
                self._tcp(ts, src, dst, pl)

    def _nuevo_sip(self, raw, ts, src, sport, dst, dport, tr, frag=False):
        try:
            self.sip.append(Sip(raw, ts, src, sport, dst, dport, tr, self.n, frag))
        except (ValueError, IndexError):
            pass

    def _udp(self, ts, src, sport, dst, dport, d, frag):
        if es_sip(d):
            self._nuevo_sip(d, ts, src, sport, dst, dport, 'UDP', frag)
        elif len(d) >= 12 and d[0] >> 6 == 2 and sport >= 1024 and dport >= 1024:
            pt = d[1] & 0x7f
            if 72 <= pt <= 76:                          # RTCP
                return
            seq, rts, ssrc = struct.unpack('!HII', d[2:12])
            self.rtp_crudo[(src, sport, dst, dport, ssrc)].append((ts, seq, rts, pt))

    def _tcp(self, ts, src, dst, seg):
        sport, dport, seq = struct.unpack('!HHI', seg[:8])
        datos = seg[(seg[12] >> 4) * 4:]
        if 5061 in (sport, dport):
            if datos:
                self.tls += 1
            return
        clave = (src, sport, dst, dport)
        st = self.tcp.get(clave)
        if seg[13] & 0x02:                              # SYN
            self.tcp[clave] = {'sig': (seq + 1) & 0xffffffff, 'buf': bytearray(), 'pend': {}}
            return
        if not datos:
            return
        if st is None:
            st = self.tcp[clave] = {'sig': seq, 'buf': bytearray(), 'pend': {}}
        if len(datos) > len(st['pend'].get(seq, b'')):
            st['pend'][seq] = datos
        self._vaciar(st)
        if len(st['pend']) > 64:                        # hueco en la captura: saltarlo
            st['sig'] = min(st['pend'], key=lambda s: (s - st['sig']) & 0xffffffff)
            st['buf'] = bytearray()
            self._vaciar(st)
        for raw in self._extraer(st['buf']):
            self._nuevo_sip(raw, ts, src, sport, dst, dport, 'TCP')

    @staticmethod
    def _vaciar(st):
        pend = st['pend']
        while pend:
            sig = st['sig']
            s = next((s for s in pend if s == sig or ((s - sig) & 0xffffffff) >= 0x80000000), None)
            if s is None:
                return
            d = pend.pop(s)
            solape = (sig - s) & 0xffffffff
            if solape < len(d):
                st['buf'] += d[solape:]
                st['sig'] = (s + len(d)) & 0xffffffff

    @staticmethod
    def _extraer(buf):
        while True:
            i = 0
            while buf[i:i + 2] == b'\r\n':
                i += 2
            if i:
                del buf[:i]
            if not buf:
                return
            m = RE_INICIO_TCP.search(buf)
            if not m:
                if len(buf) > 65536:
                    buf.clear()
                return
            if m.start():
                del buf[:m.start()]
            fin = buf.find(b'\r\n\r\n')
            if fin < 0:
                return
            cl = RE_CL.search(bytes(buf[:fin]))
            total = fin + 4 + (int(cl.group(1)) if cl else 0)
            if len(buf) < total:
                return
            yield bytes(buf[:total])
            del buf[:total]

    def _marcar_retransmisiones(self):
        vistos, limpio = {}, []
        for m in self.sip:
            k = (m.src, m.sport, m.dst, m.dport, m.primera, m.call_id, m.cseq, m.branch, m.to_tag)
            if k in vistos:
                if m.ts - vistos[k] < 0.05:             # el mismo paquete capturado dos veces
                    continue
                m.retrans = True
            vistos[k] = m.ts
            limpio.append(m)
        self.sip = limpio

# ───────────────────────────── RTP ─────────────────────────────


def mapa_sdp(sip):
    """(ip, puerto) -> rtpmap de todos los SDP vistos."""
    mapa = {}
    for m in sip:
        if m.sdp:
            for med in m.sdp['medias']:
                if med['ip'] and med['puerto']:
                    mapa[(med['ip'], med['puerto'])] = med
    return mapa


def stats_rtp(clave, pkts, mapa):
    src, sport, dst, dport, ssrc = clave
    med = mapa.get((dst, dport)) or mapa.get((src, sport))
    def info_pt(pt):
        pt = str(pt)
        if med and pt in med['rtpmap']:
            return med['rtpmap'][pt]
        return PT_ESTATICOS.get(pt, (f'PT{pt}', 8000))
    pts = Counter(p[3] for p in pkts if info_pt(p[3])[0] != 'TELEPHONE-EVENT')
    pt = pts.most_common(1)[0][0] if pts else pkts[0][3]
    codec, reloj = info_pt(pt)
    hi = lo = None
    exts, desorden = set(), 0
    for p in pkts:
        if hi is None:
            ext = hi = lo = p[1]
        else:
            ext = hi + ((p[1] - hi + 32768) % 65536 - 32768)
            if ext < hi:
                desorden += 1
            hi, lo = max(hi, ext), min(lo, ext)
        exts.add(ext)
    esperados = hi - lo + 1
    perdidos = max(0, esperados - len(exts))
    jit = jit_max = hueco = 0.0
    ant = None
    dtmf = set()
    for p in pkts:
        if p[3] != pt:
            if info_pt(p[3])[0] == 'TELEPHONE-EVENT':
                dtmf.add(p[2])
            continue
        if ant:
            dts = ((p[2] - ant[2] + 2 ** 31) % 2 ** 32) - 2 ** 31
            d = (p[0] - ant[0]) - dts / reloj
            jit += (abs(d) - jit) / 16
            jit_max = max(jit_max, jit)
            hueco = max(hueco, p[0] - ant[0])
        ant = p
    return {
        'src': src, 'sport': sport, 'dst': dst, 'dport': dport, 'ssrc': ssrc, 'codec': codec,
        'paquetes': len(pkts), 'perdidos': perdidos, 'pct': 100.0 * perdidos / esperados if esperados else 0,
        'jitter': jit * 1000, 'jitter_max': jit_max * 1000, 'hueco': hueco * 1000, 'desorden': desorden,
        't_ini': pkts[0][0], 't_fin': pkts[-1][0], 'dtmf': len(dtmf), 'en_sdp': med is not None,
    }


def flujos_rtp(cap):
    mapa = mapa_sdp(cap.sip)
    flujos = []
    for clave, todos in cap.rtp_crudo.items():
        # El mismo puerto/SSRC puede reutilizarse en llamadas distintas: separar por silencios > 30 s
        tramos, ini = [], 0
        for i in range(1, len(todos)):
            if todos[i][0] - todos[i - 1][0] > 30:
                tramos.append(todos[ini:i])
                ini = i
        tramos.append(todos[ini:])
        for pkts in tramos:
            if len(pkts) < 5:
                continue
            s = stats_rtp(clave, pkts, mapa)
            if s['en_sdp'] or (s['paquetes'] >= 50 and s['pct'] < 50):
                flujos.append(s)
    flujos.sort(key=lambda s: s['t_ini'])
    return flujos

# ───────────────────────────── Análisis de llamadas ─────────────────────────────


def nivel_codigo(c, cancelada):
    if c in (486, 600, 603) or (c == 487 and cancelada):
        return 'info'
    if c in (480, 487):
        return 'aviso'
    return 'error'


def explicar_reason(v):
    m = re.search(r'cause\s*=\s*(\d+)', v, re.I)
    if m and v.strip().upper().startswith('Q.850'):
        c = int(m.group(1))
        return f'Q.850 causa {c}: {Q850.get(c, "sin descripción")}'
    if m:
        c = int(m.group(1))
        return f'SIP {c}: {CODIGOS.get(c, "")}'.strip()
    return v


def analizar_llamada(n, msgs, flujos, hay_rtp, t_fin_captura):
    P = []
    R = {}

    def prob(nivel, txt, resumen=None):
        if (nivel, txt) not in P:
            P.append((nivel, txt))
        if resumen:
            R[resumen] = max(nivel, R.get(resumen, nivel), key=NIVELES.index)

    invs = [m for m in msgs if m.req and m.metodo == 'INVITE' and not m.to_tag] or \
           [m for m in msgs if m.req and m.metodo == 'INVITE']
    p0 = invs[0]
    A, B = p0.ep_src, p0.ep_dst
    ll = {
        'n': n, 'msgs': msgs, 'call_id': p0.call_id, 'inicio': p0.ts, 'A': A, 'B': B, 'ip_A': p0.src,
        'origen': uri_usuario(p0.h('from')), 'nombre': nombre_visible(p0.h('from')),
        'destino': uri_usuario(p0.uri), 'to': uri_usuario(p0.h('to')),
        'ua_A': p0.h('user-agent'), 'ua_B': '', 'transporte': p0.transporte,
        't_ring': None, 't_resp': None, 't_fin': None, 'duracion': None, 'colgo': '',
        'codec': '', 'problemas': P, 'rtp': [], 'codigo': None, 'parcial': bool(p0.to_tag),
        'respondida': False, 'escaneo': False, 'resumen': R,
    }
    if ll['parcial']:
        prob('info', 'La captura empieza con la llamada ya establecida (solo se ve un re-INVITE).')
    for m in msgs:
        if m.ep_src == B and (m.h('user-agent') or m.h('server')):
            ll['ua_B'] = m.h('user-agent') or m.h('server')
            break

    cseqs = sorted({m.cseq for m in invs})
    ult = cseqs[-1]
    resp_inv = [m for m in msgs if not m.req and m.cseq_metodo == 'INVITE' and m.cseq in cseqs]
    # Respuestas que recibe el llamante (las de otros tramos de la misma llamada se analizan aparte)
    resp_A = [r for r in resp_inv if r.ep_dst == A] or [r for r in resp_inv if r.dst == p0.src]
    ll['respondida'] = bool(resp_A)
    finales = [r for r in resp_A if r.codigo >= 200]
    final = next((r for r in finales if r.cseq == ult), None) or (finales[-1] if finales else None)
    ring = next((r for r in resp_A if r.codigo in (180, 183)), None)
    cancelada = any(m.req and m.metodo == 'CANCEL' for m in msgs)
    ll['t_ring'] = ring.ts if ring else None

    # Retransmisiones del INVITE y ausencia de respuesta del primer salto
    for c in cseqs:
        reqs = [m for m in msgs if m.req and m.metodo == 'INVITE' and m.cseq == c and m.ep_src == A]
        resps = [r for r in resp_A if r.cseq == c]
        if resps:
            nre = sum(1 for m in reqs[1:] if m.ts < resps[0].ts)
            if nre:
                prob('aviso', f'INVITE retransmitido {nre} vez/veces antes de recibir respuesta '
                              f'({(resps[0].ts - reqs[0].ts) * 1000:.0f} ms): pérdida de paquetes o destino lento.')
        elif reqs and c == ult and not ll['parcial'] and reqs[0].ts < t_fin_captura - 2:
            prob('error', f'El INVITE no recibió ninguna respuesta ({len(reqs)} envíos): destino inalcanzable, '
                          'firewall bloqueando, IP/puerto/transporte incorrecto o el destino ignora la IP de origen.',
                 f'{reqs[0].ep_dst} no responde a los INVITE de {reqs[0].src}')

    # INVITE reenviados por un proxy/centralita (misma Call-ID) hacia otros destinos que no contestan
    for m in msgs:
        if not (m.req and m.metodo == 'INVITE' and not m.retrans and not m.to_tag) or m is p0 or m.ep_src == A:
            continue
        resp = [r for r in msgs if not r.req and r.cseq_metodo == 'INVITE' and r.cseq == m.cseq
                and r.src == m.dst and r.dst == m.src]
        if not resp and m.ts < t_fin_captura - 2:
            nre = sum(1 for x in msgs if x.retrans and x.req and x.metodo == 'INVITE' and x.branch == m.branch
                      and x.ep_dst == m.ep_dst)
            prob('aviso', f'El INVITE reenviado a {m.ep_dst} ({uri_usuario(m.uri)}) no obtuvo respuesta '
                          f'({nre} retransmisiones): destino caído o la extensión tiene registrada una dirección '
                          'antigua/NAT caducado.',
                 f'{m.ep_dst} (usuario {uri_usuario(m.uri)}) no responde a los INVITE: dirección registrada caducada o equipo caído')

    # Estado final
    if final is None:
        ll['estado'] = 'Sin respuesta' if not resp_A else 'Sin respuesta final'
        if resp_A and p0.ts < t_fin_captura - 2:
            prob('aviso', 'Hubo respuestas provisionales pero ninguna final dentro de la captura '
                          '(¿la captura se cortó antes de terminar la llamada?).')
    else:
        c = final.codigo
        ll['codigo'] = c
        if c < 300:
            ll['estado'] = 'Contestada'
        elif c == 487 or (cancelada and c >= 400):
            ll['estado'] = 'Cancelada'
            seg = f' tras {final.ts - ring.ts:.0f} s sonando' if ring else ''
            prob('info', f'El llamante colgó antes de que contestaran{seg} (CANCEL → {c}).')
        else:
            ll['estado'] = f'Fallida {c}'
            if c in (401, 407):
                prob('error', f'{c} {final.motivo}: el llamante no reintentó con credenciales '
                              '(usuario/contraseña no configurados o rechazados).')
            elif 'not registered' in final.h('reason').lower() or 'not registered' in final.motivo.lower():
                prob('error', f'{c} {final.motivo}: la centralita indica que la extensión {ll["destino"]} NO estaba '
                              'registrada (teléfono dado de baja o sin conexión). Ver "Extensiones sin registro".',
                     f'Extensión {ll["destino"]} no registrada cuando la llamaron ({c} not registered)')
            else:
                prob(nivel_codigo(c, cancelada), f'{c} {final.motivo}: {CODIGOS.get(c, "código no habitual.")}',
                     f'Llamadas terminadas con {c} {final.motivo} (enviado por {final.ep_src})'
                     if nivel_codigo(c, cancelada) != 'info' else None)
        if len(cseqs) > 1 and c in (401, 407):
            prob('error', 'Se reintentó con credenciales y se volvieron a rechazar: usuario/contraseña incorrectos.')

    for m in msgs:
        if m.h('reason') and not m.retrans:
            prob('info', f'Reason en {m.metodo or m.codigo}: {explicar_reason(m.h("reason"))}')

    if ring and ring.ts - p0.ts > 6:
        prob('aviso', f'Retardo de marcación alto: {ring.ts - p0.ts:.1f} s hasta el primer tono (180/183).')

    # Llamada contestada: ACK, BYE, duración
    ultimo = msgs[-1].ts
    problema_ack = False
    if final is not None and final.codigo < 300:
        ll['t_resp'] = final.ts
        acks = [m for m in msgs if m.req and m.metodo == 'ACK' and m.cseq == final.cseq]
        # Cada tramo que envía un 200 OK debe recibir su ACK
        oks_por_origen = OrderedDict()
        for r in resp_inv:
            if r.codigo == final.codigo and r.cseq == final.cseq:
                oks_por_origen.setdefault(r.ep_src, []).append(r)
        for origen, oks in oks_por_origen.items():
            r = oks[0]
            buenos = [a for a in acks if a.dst == r.src and a.ts >= r.ts - 0.001]
            desviados = [a for a in acks if a.src == r.dst and a.dst != r.src and a.ts >= r.ts - 0.001]
            nret = len(oks) - 1
            if nret >= 2 or (not buenos and r.ts < t_fin_captura - 2):
                problema_ack = True
                if desviados and not buenos:
                    prob('error', f'El ACK al 200 OK de {origen} se envía a {desviados[0].ep_dst} en lugar de a {r.src}: '
                                  f'el 200 OK se retransmitió {nret} veces porque el ACK no le llega. Causa típica: '
                                  f'Contact del 200 OK con IP privada ({uri_host(r.h("contact"))}) o registro/NAT '
                                  'desactualizado en la centralita. La llamada se corta a los ~32 s.',
                         f'El ACK para {r.src} se envía a {desviados[0].dst}: las llamadas pueden cortarse a los ~32 s')
                elif not buenos:
                    prob('error', f'El 200 OK de {origen} se retransmitió {nret} veces y nunca llegó el ACK: el ACK se '
                                  'envía a una dirección incorrecta (Contact/Record-Route con IP privada, NAT o SIP ALG). '
                                  'Suele acabar cortando la llamada a los ~32 s.',
                         f'No llega el ACK al 200 OK de {r.src}: las llamadas pueden cortarse a los ~32 s')
                else:
                    prob('aviso', f'El ACK al 200 OK de {origen} llegó tarde (200 OK retransmitido {nret} veces): '
                                  'pérdida de paquetes o NAT intermitente.')
        byes = [m for m in msgs if m.req and m.metodo == 'BYE' and not m.retrans]
        if byes:
            bye = byes[0]
            ll['t_fin'] = bye.ts
            ll['duracion'] = dur = bye.ts - final.ts
            ll['colgo'] = ('llamante' if bye.ep_src == A else 'llamado' if bye.ep_src == B else
                           'llamante' if bye.src == p0.src != p0.dst else 'llamado' if bye.src == p0.dst != p0.src
                           else f'extremo {bye.ep_src}')
            rb = [r for r in msgs if not r.req and r.cseq_metodo == 'BYE' and r.cseq == bye.cseq]
            if not rb:
                if bye.ts < t_fin_captura - 2:
                    prob('aviso', 'El BYE no recibió respuesta: el otro extremo ya no es alcanzable (NAT/ruta) o ya había colgado.',
                         f'BYE de {bye.src} a {bye.dst} sin respuesta')
            elif any(r.codigo == 481 for r in rb):
                prob('aviso', 'El BYE recibió 481: el otro extremo ya no tenía la llamada (desajuste de diálogo).')
            if 28 <= dur <= 36:
                if problema_ack:
                    prob('error', f'Llamada cortada a los {dur:.0f} s: patrón clásico de ACK perdido (temporizador SIP de 32 s).',
                         'Llamadas cortadas a los ~32 s por ACK perdido')
                else:
                    prob('info', f'Duración de {dur:.0f} s: si muchas llamadas se cortan a ~30 s, sospechar de '
                                 'ACK perdido, NAT o SIP ALG.')
            se = re.match(r'\s*(\d+)', final.h('session-expires') or p0.h('session-expires'))
            if se and abs(dur - int(se.group(1))) <= 3:
                prob('aviso', f'La llamada terminó justo al vencer Session-Expires ({se.group(1)} s): '
                              'el refresco (re-INVITE/UPDATE) falló o no se envió.')
        else:
            ll['duracion'] = ultimo - final.ts
            ll['estado'] = 'Contestada (sin BYE)'
            prob('info', 'No se ve el BYE: la llamada seguía activa al terminar la captura o el BYE no se capturó.')

    # re-INVITE / UPDATE
    for m in msgs:
        if m.req and m.metodo in ('INVITE', 'UPDATE') and m.to_tag and not m.retrans and m.cseq not in cseqs:
            rs = [r for r in msgs if not r.req and r.cseq_metodo == m.metodo and r.cseq == m.cseq and r.codigo >= 200
                  and r.src == m.dst]
            if not rs and m.ts < t_fin_captura - 2:
                prob('aviso', f're-{m.metodo} de {m.ep_src} a {m.ep_dst} (CSeq {m.cseq}) sin respuesta final.')
            elif rs and rs[0].codigo >= 300:
                prob('aviso', f're-{m.metodo} rechazado con {rs[0].codigo} {rs[0].motivo}: '
                              f'{CODIGOS.get(rs[0].codigo, "")}')

    # SDP: NAT, códecs, espera
    sintomas = problema_ack or any('BYE' in t for _, t in P)
    nivel_nat = 'aviso' if sintomas else 'info'
    dirs = {}
    for m in msgs:
        if m.retrans:
            continue
        cont = uri_host(m.h('contact'))
        if cont and es_privada(cont) and es_publica(m.src):
            prob(nivel_nat, f'Contact con IP privada {cont} en un mensaje que llega desde la IP pública {m.src}: '
                            'el equipo está tras NAT y no lo corrige; depende de que la centralita/proveedor lo arregle. '
                            + ('Aquí SÍ hay síntomas (ACK/BYE que no llegan).' if sintomas else 'En esta llamada no causó síntomas.'),
                 f'Equipos tras NAT en {m.src} anuncian IP privada en Contact/SDP' if sintomas else None)
        med = audio(m.sdp)
        if not med:
            continue
        lado = 'A' if m.ep_src == A or (m.src == p0.src != p0.dst) else 'B'
        ip = med['ip']
        if ip and es_privada(ip) and es_publica(m.src):
            prob(nivel_nat, f'SDP con IP privada {ip} enviado desde la IP pública {m.src}: si nadie corrige el NAT, '
                            'el audio irá a una IP no alcanzable → audio unidireccional o sin audio.')
        if ip == '0.0.0.0' or med['dir'] in ('sendonly', 'inactive'):
            prob('info', f'{m.etiqueta()} de {m.ep_src}: SDP en modo '
                         f'{"0.0.0.0" if ip == "0.0.0.0" else med["dir"]} → llamada puesta en espera.')
        if ip and ip != '0.0.0.0' and med['puerto']:
            dirs[(ip, med['puerto'])] = lado
    oferta = next((audio(m.sdp) for m in msgs if m.req and m.metodo == 'INVITE' and m.ep_src == A and audio(m.sdp)), None)
    resp = next((audio(m.sdp) for m in resp_A if audio(m.sdp)), None)
    if resp:
        cods = [c for c in resp['codecs'] if c not in NO_AUDIO]
        ll['codec'] = cods[0] if cods else ''
        if resp['puerto'] == 0:
            prob('error', 'El destino rechazó el audio en el SDP (puerto 0).')
    if oferta and resp:
        comunes = [c for c in resp['codecs'] if c in oferta['codecs'] and c not in NO_AUDIO]
        if not comunes and resp['puerto']:
            prob('error', f'Sin códec común: oferta {", ".join(oferta["codecs"])} / respuesta {", ".join(resp["codecs"])}.')
        if 'TELEPHONE-EVENT' in oferta['codecs'] and 'TELEPHONE-EVENT' not in resp['codecs']:
            prob('info', 'DTMF RFC 2833 ofrecido pero no aceptado: los tonos (menús IVR, PIN) pueden no funcionar.')
    elif oferta is None and not ll['parcial'] and ll['t_resp']:
        prob('info', 'INVITE sin SDP (oferta tardía: el SDP va en el 200 OK y la respuesta en el ACK).')

    # Fragmentación
    for m in msgs:
        if m.transporte == 'UDP' and len(m.raw) > 1300:
            prob('aviso' if not ll['respondida'] else 'info',
                 f'Mensaje SIP de {len(m.raw)} bytes por UDP ({m.etiqueta()}): riesgo de fragmentación; '
                 'si hay INVITE que no llegan, probar SIP sobre TCP.')
            break
    if any(m.frag for m in msgs):
        prob('aviso', 'Algún mensaje SIP llegó fragmentado a nivel IP (hay routers/firewalls que descartan fragmentos).',
             'Mensajes SIP fragmentados a nivel IP')

    # RTP
    t_a, t_b = p0.ts, (ll['t_fin'] or ultimo) + 5
    puertos_privados = {p: l for (ip, p), l in dirs.items() if es_privada(ip)}
    for s in flujos:
        if s['t_fin'] < t_a or s['t_ini'] > t_b:
            continue
        if (s['dst'], s['dport']) in dirs:
            hacia = dirs[(s['dst'], s['dport'])]
        elif (s['src'], s['sport']) in dirs:
            hacia = 'B' if dirs[(s['src'], s['sport'])] == 'A' else 'A'
        elif s['dport'] in puertos_privados:
            hacia = puertos_privados[s['dport']]
        else:
            continue
        ll['rtp'].append(dict(s, hacia=hacia))
    if hay_rtp and ll['t_resp']:
        a_A = [s for s in ll['rtp'] if s['hacia'] == 'A']
        a_B = [s for s in ll['rtp'] if s['hacia'] == 'B']
        if not a_A and not a_B:
            prob('aviso', 'Llamada contestada pero no se ve RTP: el audio no pasa por el punto de captura, '
                          'o está bloqueado (firewall/NAT).', 'Llamadas contestadas sin audio (RTP) visible')
        elif not a_A:
            prob('error', 'Audio unidireccional: no llega audio hacia el LLAMANTE (no oye). '
                          'Revisar NAT/IP del SDP del llamado y firewall.', 'Audio unidireccional (el llamante no oye)')
        elif not a_B:
            prob('error', 'Audio unidireccional: no llega audio hacia el LLAMADO (no oye). '
                          'Revisar NAT/IP del SDP del llamante y firewall.', 'Audio unidireccional (el llamado no oye)')
        for s in ll['rtp']:
            sentido = f'hacia el {"llamante" if s["hacia"] == "A" else "llamado"}'
            if s['pct'] > 5:
                prob('error', f'Pérdida de RTP {sentido}: {s["pct"]:.1f}% ({s["perdidos"]} paquetes) → cortes de voz.',
                     f'Pérdida de audio > 5% en flujos hacia {s["dst"]}')
            elif s['pct'] > 1:
                prob('aviso', f'Pérdida de RTP {sentido}: {s["pct"]:.1f}%.', f'Pérdida de audio 1-5% en flujos hacia {s["dst"]}')
            if s['jitter_max'] > 30:
                prob('aviso', f'Jitter alto {sentido}: máx {s["jitter_max"]:.0f} ms (voz entrecortada/robótica).',
                     f'Jitter alto en flujos hacia {s["dst"]}')
            if s['hueco'] > 500:
                prob('aviso', f'Hueco de {s["hueco"]:.0f} ms sin RTP {sentido} (silencio o microcorte).')
    return ll


ESCANERES = re.compile(r'friendly-scanner|sipvicious|sipcli|pplsip|sundayddr|vaxsip|iwar|sip-?scan|sipsak|smap|'
                       r'siparmyknife|voipbuster|sippts|sipptk', re.I)


def detectar_escaneos(llamadas, sip):
    """Marca como escaneo/ataque las llamadas de IPs públicas que solo hacen intentos sin éxito."""
    # IPs con relación legítima: registros u OPTIONS con éxito
    legitimas = set()
    for m in sip:
        if not m.req and m.codigo < 300 and m.cseq_metodo in ('REGISTER', 'OPTIONS'):
            legitimas.update((m.src, m.dst))
    por_ip = defaultdict(list)
    for ll in llamadas:
        por_ip[ll['ip_A']].append(ll)
    ataques = []
    for ip, lls in por_ip.items():
        if not es_publica(ip):
            continue
        uas = Counter(ll['ua_A'] for ll in lls)
        conocido = any(ESCANERES.search(u or '') for u in uas)
        sin_exito = not any(ll['t_resp'] for ll in lls) and all(ll['codigo'] in (None, 401, 403, 404, 407, 484) for ll in lls)
        internacional = sum(1 for ll in lls if re.match(r'^(\+|00|011|9011)', ll['destino'] or '')
                            and not re.match(r'^(\+|00)34', ll['destino'] or ''))
        ignoradas = not any(ll['respondida'] for ll in lls)
        sospechoso = conocido or (sin_exito and ip not in legitimas and (
            ignoradas or (len(lls) >= 3 and (len(uas) >= 3 or internacional >= len(lls) / 2))))
        if not sospechoso:
            continue
        resp = Counter(str(ll['codigo']) if ll['codigo'] else ('sin respuesta' if not ll['respondida'] else 'otra')
                       for ll in lls)
        for ll in lls:
            ll['escaneo'] = True
            if ll['t_resp']:
                ll['estado'] = 'POSIBLE FRAUDE'
                ll['problemas'].insert(0, ('error', f'¡Llamada CONTESTADA desde una IP sospechosa ({ip})! '
                                                    'Posible fraude telefónico: revisar la centralita y bloquear la IP.'))
            else:
                ll['estado'] = 'Escaneo/ataque?'
                ll['problemas'][:] = [('info', f'Intento sospechoso desde {ip} (escáner o fraude telefónico). '
                                               'No tuvo éxito: la centralita lo bloqueó correctamente.')]
        ataques.append({'ip': ip, 'llamadas': len(lls), 'uas': uas, 'destinos': Counter(ll['destino'] for ll in lls),
                        'origenes': Counter(ll['origen'] for ll in lls), 'respuestas': resp,
                        'inicio': lls[0]['inicio'], 'fin': lls[-1]['inicio'], 'conocido': conocido,
                        'exito': any(ll['t_resp'] for ll in lls)})
    return ataques


# ───────────────────────────── Registros y OPTIONS ─────────────────────────────


def indice_respuestas(msgs):
    idx = defaultdict(list)
    for m in msgs:
        if not m.req:
            idx[(m.call_id, m.cseq, m.cseq_metodo)].append(m)
    return idx


def analizar_registros(sip, t_fin):
    idx = indice_respuestas(sip)
    regs = OrderedDict()
    previo = {}
    for m in sip:
        if not (m.req and m.metodo == 'REGISTER') or m.retrans:
            continue
        aor = uri_usuario(m.h('to')) + '@' + uri_host(m.h('to'))
        r = regs.setdefault((aor, m.src), {'aor': aor, 'src': m.src, 'dst': m.dst, 'ua': m.h('user-agent'),
                                           'total': 0, 'ok': 0, 'retos': 0, 'codigos': Counter(),
                                           'sin_resp': 0, 'cred_mal': 0, 'expires': None, 'ultimo': None,
                                           'contact': uri_host(m.h('contact')), 'problemas': []})
        r['total'] += 1
        anterior = previo.get((aor, m.src))
        rs = [x for x in idx[(m.call_id, m.cseq, 'REGISTER')] if x.codigo >= 200]
        if not rs:
            if m.ts < t_fin - 2:
                r['sin_resp'] += 1
                r['ultimo'] = 'sin respuesta'
            continue
        c = rs[0].codigo
        r['codigos'][c] += 1
        r['ultimo'] = c
        previo[(aor, m.src)] = c
        if c < 300:
            r['ok'] += 1
            e = re.search(r'expires=(\d+)', rs[0].h('contact'), re.I)
            r['expires'] = int(e.group(1)) if e else (int(rs[0].h('expires')) if rs[0].h('expires').isdigit() else r['expires'])
        elif c in (401, 407):
            r['retos'] += 1
            auth = m.h('authorization') or m.h('proxy-authorization')
            reto = rs[0].h('www-authenticate') or rs[0].h('proxy-authenticate')
            if auth and anterior in (401, 407) and 'stale=true' not in reto.lower():
                r['cred_mal'] += 1
    for r in regs.values():
        P = r['problemas']
        if r['cred_mal']:
            P.append(('error', f'Credenciales rechazadas {r["cred_mal"]} vez/veces al responder a un reto 401/407: '
                               'usuario, contraseña o usuario de autenticación incorrectos.'))
        for c, k in r['codigos'].items():
            if c >= 300 and c not in (401, 407):
                P.append(('error', f'{k}× {c}: {CODIGOS.get(c, "código no habitual.")}'))
        if r['sin_resp']:
            P.append(('error', f'{r["sin_resp"]} REGISTER sin respuesta: servidor inaccesible, firewall, o IP/DNS/puerto del proveedor erróneo.'))
        if r['total'] and not r['ok']:
            P.append(('error', 'No consiguió registrarse ni una vez en toda la captura.'))
        if r['contact'] and es_privada(r['contact']) and es_publica(r['src']):
            P.append(('aviso', f'Contact con IP privada {r["contact"]} desde la IP pública {r["src"]}: '
                               'las llamadas entrantes pueden no llegar (NAT).'))
        if r['expires'] is not None and r['expires'] < 60:
            P.append(('info', f'Expires muy corto ({r["expires"]} s): registro muy frecuente (suele ser keepalive de NAT).'))
        if r['ok'] and r['ultimo'] == 200 and not P:
            P.append(('ok', 'Registro correcto.'))
    return list(regs.values())


def analizar_options(sip, t_fin):
    idx = indice_respuestas(sip)
    envios = defaultdict(list)
    for m in sip:
        if m.req and m.metodo == 'OPTIONS':
            envios[(m.call_id, m.cseq, m.ep_src)].append(m.ts)
    grupos = OrderedDict()
    for m in sip:
        if not (m.req and m.metodo == 'OPTIONS') or m.retrans:
            continue
        g = grupos.setdefault((m.src, m.sport, m.dst, m.dport),
                              {'src': f'{m.src}:{m.sport}', 'dst': f'{m.dst}:{m.dport}', 'uri': m.uri,
                               'ua': m.h('user-agent'), 'envios': [], 'codigos': Counter(), 'rtt': [],
                               'retx': 0, 'problemas': []})
        rs = idx[(m.call_id, m.cseq, 'OPTIONS')]
        ts_env = envios[(m.call_id, m.cseq, m.ep_src)]
        g['retx'] += len(ts_env) - 1
        if rs:
            g['codigos'][rs[0].codigo] += 1
            g['rtt'].append(rs[0].ts - max([t for t in ts_env if t <= rs[0].ts] or [m.ts]))
            g['envios'].append((m.ts, True))
        elif m.ts < t_fin - 2:
            g['envios'].append((m.ts, False))
    salida = []
    for g in grupos.values():
        env = g['envios']
        g['total'] = len(env)
        g['resp'] = sum(1 for _, ok in env if ok)
        g['sin'] = g['total'] - g['resp']
        g['rtt_med'] = sum(g['rtt']) / len(g['rtt']) * 1000 if g['rtt'] else None
        cortes, ini, n = [], None, 0
        for ts, ok in env + [(None, True)]:
            if not ok:
                ini = ini or ts
                fin, n = ts, n + 1
            elif ini:
                cortes.append((ini, fin, n))
                ini, n = None, 0
        g['cortes'] = cortes
        if g['total'] and not g['resp']:
            g['problemas'].append(('error', f'El destino no respondió a ninguno de los {g["total"]} OPTIONS: enlace caído, bloqueado o mal direccionado.'))
        elif g['sin']:
            txt = ', '.join(f'{fmt_hora(a)}–{fmt_hora(b)} ({k})' for a, b, k in cortes[:5])
            g['problemas'].append(('aviso', f'{g["sin"]} de {g["total"]} OPTIONS sin respuesta. Cortes: {txt}'
                                            + (' …' if len(cortes) > 5 else '')))
        if g['rtt_med'] and g['rtt_med'] > 300:
            g['problemas'].append(('aviso', f'Tiempo de respuesta medio alto: {g["rtt_med"]:.0f} ms.'))
        if g['total'] and g['resp'] and g['retx'] > g['total'] * 0.05:
            g['problemas'].append(('aviso', f'{g["retx"]} retransmisiones para {g["total"]} OPTIONS: '
                                            'se pierden paquetes en el camino (o el extremo tarda > 500 ms en contestar).'))
        if not g['problemas']:
            g['problemas'].append(('ok', 'Responde siempre.'))
        g['peor'] = 0 if g['problemas'][0][0] == 'ok' else 2 if any(p[0] == 'error' for p in g['problemas']) else 1
        salida.append(g)
    salida.sort(key=lambda g: -g['peor'])
    return salida

def contactos(m):
    """Contactos vigentes que lista un 200 OK a REGISTER: [(uri, expires)]."""
    out = []
    for k, v in m.cabeceras:
        if k != 'contact':
            continue
        for c in re.split(r',\s*(?=<|sips?:)', v):
            if c.strip() and c.strip() != '*':
                e = re.search(r'expires=(\d+)', c, re.I)
                out.append((uri_host(c), int(e.group(1)) if e else None))
    return out


def analizar_bajas(sip, llamadas, t_fin):
    """Periodos en los que una extensión se queda sin ningún registro en la centralita.

    Se basa en los 200 OK a REGISTER, que listan todos los contactos vigentes: si la lista llega
    vacía, la extensión se ha quedado sin registro. También detecta registros que caducan sin renovarse.
    """
    peticiones = {(m.call_id, m.cseq): m for m in sip if m.req and m.metodo == 'REGISTER'}
    abiertas, caduca, bajas = {}, {}, []

    def abrir(aor, ts, causa, req):
        if aor not in abiertas:
            abiertas[aor] = {'aor': aor, 'ext': aor.split('@')[0], 'inicio': ts, 'causa': causa,
                             'ep': req.ep_src if req else '', 'ua': req.h('user-agent') if req else ''}

    def cerrar(aor, ts):
        if aor in abiertas:
            b = abiertas.pop(aor)
            b['fin'] = ts
            bajas.append(b)

    for r in sip:
        if r.req or r.retrans or r.cseq_metodo != 'REGISTER' or r.codigo != 200:
            continue
        aor = uri_usuario(r.h('to')) + '@' + uri_host(r.h('to'))
        req = peticiones.get((r.call_id, r.cseq))
        if aor in caduca and r.ts > caduca[aor] + 1:
            abrir(aor, caduca[aor], 'caducó', req)
        cs = contactos(r)
        if cs:
            cerrar(aor, r.ts)
            exp = [e for _, e in cs if e is not None] or ([int(r.h('expires'))] if r.h('expires').isdigit() else [3600])
            caduca[aor] = r.ts + max(exp)
        else:
            caduca.pop(aor, None)
            abrir(aor, r.ts, 'baja', req)
    for aor, t in caduca.items():
        if t < t_fin:
            abrir(aor, t, 'caducó', None)
    for aor in list(abiertas):
        cerrar(aor, None)

    for b in bajas:
        fin = b['fin'] or t_fin
        b['duracion'] = fin - b['inicio']
        b['llamadas'] = [ll['n'] for ll in llamadas if not ll['escaneo'] and b['inicio'] <= ll['inicio'] <= fin
                         and b['ext'] in {ll['destino'], ll['to']} | {uri_usuario(m.uri) for m in ll['msgs']
                                                                       if m.req and m.metodo == 'INVITE'}]
        if b['causa'] == 'baja':
            b['texto'] = (f'El propio teléfono se dio de baja (REGISTER expires=0) desde {b["ep"]}'
                          + (f' [{b["ua"]}]' if b['ua'] else '') + ' y la extensión se quedó sin ningún registro.')
        else:
            b['texto'] = ('El registro caducó sin renovarse: el teléfono dejó de enviar REGISTER '
                          '(apagado, sin red, Wi-Fi caída o NAT que bloquea).')
        b['nivel'] = 'error' if b['llamadas'] or b['duracion'] > 120 else 'aviso'
    # Las bajas de un instante dentro de un re-registro (ráfagas) no son averías
    return [b for b in bajas if b['duracion'] > 5 or b['llamadas']]


def analizar_terminales(sip, options, bajas, cap=None):
    """Calidad de cada teléfono registrado: tiempo de respuesta, cortes de keepalive y bajas."""
    idx = indice_respuestas(sip)
    # Solo teléfonos que llegaron a registrarse; se excluyen los registradores (la propia centralita)
    registradores = {r.src for r in sip if not r.req and r.cseq_metodo == 'REGISTER' and r.codigo == 200}
    registrados = {r.ep_dst for r in sip if not r.req and r.cseq_metodo == 'REGISTER' and r.codigo == 200}
    terms = OrderedDict()
    for m in sip:
        if (m.req and m.metodo == 'REGISTER' and not m.retrans and m.ep_src not in terms
                and m.ep_src in registrados and m.src not in registradores and m.src != '127.0.0.1'):
            terms[m.ep_src] = {'ep': m.ep_src, 'ip': m.src, 'ext': uri_usuario(m.h('to')), 'ua': m.h('user-agent'),
                               'lat': [], 'rafagas': 0, 'problemas': []}
    envios = defaultdict(list)
    for m in sip:
        if m.req and m.ep_dst in terms:
            envios[(m.call_id, m.cseq, m.metodo, m.ep_dst)].append(m.ts)
    for m in sip:
        if not m.req or m.retrans or m.ep_dst not in terms or m.metodo in ('ACK', 'CANCEL'):
            continue
        rs = [r for r in idx[(m.call_id, m.cseq, m.metodo)] if r.src == m.dst]
        if rs:
            t_env = max([t for t in envios[(m.call_id, m.cseq, m.metodo, m.ep_dst)] if t <= rs[0].ts] or [m.ts])
            terms[m.ep_dst]['lat'].append((rs[0].ts - t_env) * 1000)
    # Ráfagas de re-registro por detección de NAT: baja de la IP privada + alta con la pública en < 1 s
    regs = [m for m in sip if m.req and m.metodo == 'REGISTER' and not m.retrans and m.ep_src in terms]
    for i, m in enumerate(regs):
        if m.h('expires') == '0' and es_privada(uri_host(m.h('contact'))):
            if any(x.ep_src == m.ep_src and abs(x.ts - m.ts) < 1 and x.h('expires') != '0'
                   and not es_privada(uri_host(x.h('contact'))) for x in regs[max(0, i - 6):i + 6]):
                terms[m.ep_src]['rafagas'] += 1

    # "Sordera": el teléfono repite una petición aunque la centralita ya le había contestado → las respuestas
    # hacia el teléfono se pierden por el camino (el sentido teléfono → centralita sí funciona)
    tx, resp = defaultdict(list), defaultdict(list)
    for m in sip:
        if m.req and m.ep_src in terms and m.metodo != 'ACK':
            tx[(m.ep_src, m.call_id, m.cseq, m.metodo)].append(m.ts)
        elif not m.req and m.ep_dst in terms:
            resp[(m.ep_dst, m.call_id, m.cseq, m.cseq_metodo)].append(m.ts)
    for t in terms.values():
        t.update(tx_total=0, sordas=[])
    for k, ts in tx.items():
        t = terms[k[0]]
        t['tx_total'] += 1
        rs = resp.get(k)
        if len(ts) > 1 and rs and rs[0] < ts[1]:
            t['sordas'].append((ts[0], ts[-1] - ts[0], len(ts) - 1))
    for t in terms.values():
        v = sorted(t['lat'])
        t['n'] = len(v)
        t['mediana'] = v[len(v) // 2] if v else None
        t['p90'] = v[int(len(v) * 0.9)] if v else None
    for t in terms.values():
        P = t['problemas']
        pares = [x['mediana'] for x in terms.values() if x['ip'] == t['ip'] and x is not t and x['mediana'] is not None and x['n'] >= 10]
        if t['mediana'] is not None and t['n'] >= 10:
            ref = sorted(pares)[len(pares) // 2] if pares else None
            if ref is not None and t['mediana'] > 300 and t['mediana'] > 5 * ref:
                P.append(('aviso', f'Responde muy lento: {t["mediana"]:.0f} ms de mediana frente a {ref:.0f} ms del resto de '
                                   f'teléfonos de su misma IP ({t["ip"]}). La red de la oficina va bien, el problema es '
                                   'el enlace de este teléfono: típico de Wi-Fi con ahorro de energía o mala cobertura.'))
            elif ref is None and t['mediana'] > 500:
                P.append(('aviso', f'Responde muy lento: {t["mediana"]:.0f} ms de mediana (posible Wi-Fi, ahorro de energía '
                                   'o red congestionada).'))
        if t['sordas']:
            peor = max(t['sordas'], key=lambda x: x[1])
            sanos = [x for x in terms.values() if x['ip'] == t['ip'] and x is not t and x['tx_total'] >= 5 and not x['sordas']]
            comp = (f' El resto de teléfonos de su misma IP ({len(sanos)}) no pierden ninguna, así que no es la conexión '
                    'de la oficina sino el último tramo hasta este teléfono (Wi-Fi, ahorro de energía).') if sanos else ''
            P.append(('error' if peor[1] >= 4 else 'aviso',
                      f'No le llegan las respuestas de la centralita: en {len(t["sordas"])} de {t["tx_total"]} peticiones tuvo que '
                      f'repetir aunque la centralita ya había contestado. El peor caso, a las {fmt_hora(peor[0])}, estuvo '
                      f'{peor[1]:.1f} s "sordo" ({peor[2]} repeticiones). Lo que envía el teléfono llega, pero lo que se le '
                      f'envía se pierde: una llamada entrante en ese momento no le llega (408/fuera de servicio).{comp}'))
        for g in options:
            if g['dst'] == t['ep'] and g['total']:
                largos = [(a, b, k) for a, b, k in g['cortes'] if k >= 2]
                t['options'] = f'{g["resp"]}/{g["total"]}'
                if largos:
                    peor = max(largos, key=lambda c: c[1] - c[0])
                    P.append(('aviso', f'{len(largos)} corte(s) de conexión (keepalive sin respuesta ≥ 1 min); el peor: '
                                       f'{fmt_hora(peor[0])} – {fmt_hora(peor[1])} ({fmt_dur(peor[1] - peor[0] + 30)}). '
                                       'Las llamadas en esos periodos no le llegan.'))
        for b in bajas:
            if b['ep'] == t['ep']:
                P.append((b['nivel'], f'Se dio de baja a las {fmt_hora(b["inicio"])} y estuvo {fmt_dur(b["duracion"])} '
                                      f'sin registro' + (f' ({len(b["llamadas"])} llamadas afectadas).' if b['llamadas'] else '.')))
        mac = cap.mac_de_ip.get(t['ip']) if cap else None
        if mac:
            reconex = sorted({int(ts) for ts, d, o in cap.eapol if mac in (d, o)})
            if reconex:
                rereg = [m.ts for m in regs if m.ep_src == t['ep'] and m.cseq <= 2
                         and any(0 <= m.ts - r <= 60 for r in reconex)]
                P.append(('aviso', f'Se reconectó a la Wi-Fi {len(reconex)} vez/veces (handshake WPA a las '
                                   + ', '.join(fmt_hora(r)[:8] for r in reconex[:5])
                                   + (')' if not rereg else ') y justo después tuvo que registrarse de nuevo desde cero')
                                   + ': el teléfono se cae de la Wi-Fi. Mientras está desconectado no recibe llamadas.'))
        if t['rafagas']:
            P.append(('info', f'{t["rafagas"]} ráfaga(s) de REGISTER: se registra con su IP privada, ve en el 200 OK que está '
                              'tras NAT, se da de baja y se vuelve a registrar con la IP pública, todo en < 1 s. '
                              'Es inofensivo (el 200 OK sí llega); se evita fijando el NAT en la configuración del teléfono.'))
        if not P:
            P.append(('ok', 'Sin problemas.'))
        t['peor'] = max((NIVELES.index(p[0]) for p in P), default=0)
    return sorted(terms.values(), key=lambda t: (-t['peor'], t['ext']))


# ───────────────────────────── Análisis global ─────────────────────────────


class Informe:
    def __init__(self, cap):
        self.cap = cap
        self.flujos = flujos_rtp(cap)
        grupos = OrderedDict()
        for m in cap.sip:
            grupos.setdefault(m.call_id, []).append(m)
        t1 = cap.t1 or 0
        self.llamadas = []
        self.otros = Counter()
        for msgs in grupos.values():
            if any(m.req and m.metodo == 'INVITE' for m in msgs):
                self.llamadas.append(analizar_llamada(len(self.llamadas) + 1, msgs, self.flujos, bool(self.flujos), t1))
            else:
                for m in msgs:
                    if m.req and m.metodo not in ('REGISTER', 'OPTIONS') and not m.retrans:
                        self.otros[m.metodo] += 1
        self.ataques = detectar_escaneos(self.llamadas, cap.sip)
        self.registros = analizar_registros(cap.sip, t1)
        self.options = analizar_options(cap.sip, t1)
        self.bajas = analizar_bajas(cap.sip, self.llamadas, t1)
        self.terminales = analizar_terminales(cap.sip, self.options, self.bajas, cap)
        self.errores = Counter(f'{m.codigo} {m.motivo}' for m in cap.sip if not m.req and m.codigo >= 400 and not m.retrans)
        self.notas = []
        if not self.flujos and self.llamadas:
            self.notas.append('La captura no contiene RTP (audio): solo se puede analizar la señalización.')
        if cap.tls:
            self.notas.append(f'Hay {cap.tls} paquetes de SIP sobre TLS (puerto 5061), cifrados: no se pueden analizar.')
        if not cap.sip:
            self.notas.append('No se ha encontrado ningún mensaje SIP. ¿Se capturó en la interfaz o el puerto correctos?')


def agrupar_averias(llamadas, options):
    """Agrupa los problemas repetidos de varias llamadas en causas raíz."""
    agg = {}
    for ll in llamadas:
        if ll['escaneo'] and not ll['t_resp']:
            continue
        for txt, nivel in ll['resumen'].items():
            a = agg.setdefault(txt, {'nivel': nivel, 'llamadas': []})
            a['llamadas'].append(ll['n'])
            a['nivel'] = max(a['nivel'], nivel, key=NIVELES.index)
    mudos = {g['dst'] for g in options if g['total'] and not g['resp']}
    for txt, a in agg.items():
        if txt.split(' ', 1)[0] in mudos:
            a['extra'] = 'Tampoco responde a los OPTIONS (keepalive): el destino está caído o es una dirección antigua.'
    return sorted(agg.items(), key=lambda kv: (-NIVELES.index(kv[1]['nivel']), -len(kv[1]['llamadas'])))


def contar(problemas):
    return sum(1 for p in problemas if p[0] == 'error'), sum(1 for p in problemas if p[0] == 'aviso')


def filtrar(llamadas, numero, solo_problemas, ataques=False):
    r = llamadas if ataques else [ll for ll in llamadas if not ll['escaneo'] or ll['t_resp']]
    if numero:
        r = [ll for ll in r if any(numero in (ll[k] or '') for k in ('origen', 'destino', 'to', 'nombre'))]
    if solo_problemas:
        r = [ll for ll in r if any(contar(ll['problemas']))]
    return r

# ───────────────────────────── Salida por terminal ─────────────────────────────


class Color:
    activo = sys.stdout.isatty()

    @classmethod
    def c(cls, cod, s):
        return f'\033[{cod}m{s}\033[0m' if cls.activo else s


ICONO = {'error': ('31', '✖'), 'aviso': ('33', '⚠'), 'info': ('36', 'ℹ'), 'ok': ('32', '✔')}


def fmt_hora(ts):
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')[:-3] if ts else '-'


def fmt_dur(s):
    if s is None:
        return '-'
    s = int(round(s))
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f'{h}h{m:02d}m{s:02d}s' if h else f'{m}m{s:02d}s' if m else f'{s}s'


def corta(s, n):
    s = s or ''
    return s if len(s) <= n else s[:n - 1] + '…'


def titulo(t):
    print('\n' + Color.c('1;34', f'══ {t} ' + '═' * max(0, 70 - len(t))))


def linea_prob(p, sangria='  '):
    col, ic = ICONO[p[0]]
    print(sangria + Color.c(col, ic) + ' ' + p[1])


def color_estado(ll):
    e = ll['estado']
    col = '32' if e.startswith('Contestada') else '36' if e == 'Cancelada' else '31'
    return col


def imprimir_resumen(inf, llamadas, detalle=False):
    cap = inf.cap
    titulo('Captura')
    print(f'  Archivo:   {cap.path}')
    if cap.t0:
        print(f'  Periodo:   {datetime.fromtimestamp(cap.t0):%d/%m/%Y %H:%M:%S} → '
              f'{datetime.fromtimestamp(cap.t1):%H:%M:%S}  ({fmt_dur(cap.t1 - cap.t0)})')
    trans = Counter(m.transporte for m in cap.sip)
    print(f'  Paquetes:  {cap.n}   Mensajes SIP: {len(cap.sip)} '
          f'({", ".join(f"{k} {v}" for k, v in trans.items()) or "-"})   Flujos RTP: {len(inf.flujos)}')
    print(f'  Llamadas:  {len(inf.llamadas)}   Registros: {len(inf.registros)}   '
          f'Keepalives OPTIONS: {len(inf.options)}   Otros: '
          f'{", ".join(f"{k} {v}" for k, v in inf.otros.most_common()) or "-"}')
    for n in inf.notas:
        linea_prob(('info', n))
    if inf.errores:
        print('  Respuestas de error: ' + ', '.join(f'{v}× {k}' for k, v in inf.errores.most_common(8)))

    averias = agrupar_averias(llamadas, inf.options)
    if averias:
        titulo('Resumen de averías (agrupadas)')
        for txt, a in averias:
            ls = a['llamadas']
            refs = ', '.join(f'#{x}' for x in ls[:8]) + (' …' if len(ls) > 8 else '')
            linea_prob((a['nivel'], f'{txt}  ' + Color.c('90', f'[{len(ls)} llamada{"s" if len(ls) > 1 else ""}: {refs}]')))
            if a.get('extra'):
                print('     ' + Color.c('90', '↳ ' + a['extra']))

    if inf.bajas:
        titulo('Extensiones sin registro (el teléfono se cayó o se dio de baja)')
        for b in inf.bajas:
            fin = fmt_hora(b['fin']) if b['fin'] else 'fin de la captura'
            linea_prob((b['nivel'], Color.c('1', f'Ext. {b["ext"]}') + f'  sin registro de {fmt_hora(b["inicio"])} a {fin} '
                                    f'({fmt_dur(b["duracion"])})'))
            print(f'     {b["texto"]}')
            if b['llamadas']:
                print('     ' + Color.c('31', 'Llamadas que no le llegaron: ' + ', '.join(f'#{x}' for x in b['llamadas'])))

    ocultas = sum(1 for ll in inf.llamadas if ll['escaneo'] and not ll['t_resp'] and ll not in llamadas)
    titulo(f'Llamadas ({len(llamadas)} de {len(inf.llamadas)})')
    if ocultas:
        print(Color.c('90', f'  ({ocultas} intentos de escaneo/ataque ocultos: ver más abajo o usar -a para incluirlos)'))
    if not llamadas:
        print('  (ninguna)')
    else:
        print(Color.c('1', f'  {"#":>3}  {"Hora":12}  {"Origen":18}  {"Destino":18}  {"Estado":21}  {"Duración":>8}  {"Códec":6}  Problemas'))
        for ll in llamadas:
            e, a = contar(ll['problemas'])
            pr = (Color.c('31', f'✖{e} ') if e else '') + (Color.c('33', f'⚠{a}') if a else '') or Color.c('32', '✔')
            print(f'  {ll["n"]:>3}  {fmt_hora(ll["inicio"])}  {corta(ll["origen"], 18):18}  {corta(ll["destino"], 18):18}  '
                  + Color.c(color_estado(ll), f'{corta(ll["estado"], 21):21}')
                  + f'  {fmt_dur(ll["duracion"]):>8}  {corta(ll["codec"], 6):6}  {pr}')

    con = [ll for ll in llamadas if any(contar(ll['problemas']))]
    if con and not detalle and len(con) > 25:
        print(Color.c('90', f'\n  {len(con)} llamadas con errores o avisos. Para ver el detalle de cada una: '
                            'sipcap <captura> -p   (o -n <número>, o -l <nº de llamada>)'))
    elif con:
        titulo('Problemas en llamadas')
        for ll in con:
            print(Color.c('1', f'  #{ll["n"]} {fmt_hora(ll["inicio"])} {ll["origen"]} → {ll["destino"]}  [{ll["estado"]}]'))
            for p in ll['problemas']:
                if p[0] in ('error', 'aviso'):
                    linea_prob(p, '     ')
        print(Color.c('90', '\n  Detalle y diagrama de una llamada:  sipcap <captura> -l <número>'))

    if inf.ataques:
        titulo('Intentos sospechosos (escaneos / fraude)')
        for at in inf.ataques:
            col, ic = ('31', '✖') if at['exito'] else ('33', '⚠')
            print('  ' + Color.c(col, ic) + Color.c('1', f' {at["ip"]}') +
                  f'  {at["llamadas"]} INVITE entre {fmt_hora(at["inicio"])} y {fmt_hora(at["fin"])}'
                  + ('  ' + Color.c('31', '¡ALGUNA CONTESTADA!') if at['exito'] else ''))
            print(f'     User-Agent: {", ".join(u or "(vacío)" for u, _ in at["uas"].most_common(4))}'
                  + (f' (+{len(at["uas"]) - 4} distintos)' if len(at['uas']) > 4 else ''))
            print(f'     Destinos:   {", ".join(d for d, _ in at["destinos"].most_common(4))}'
                  + (' …' if len(at['destinos']) > 4 else ''))
            print(f'     Respuesta:  {", ".join(f"{k} ×{v}" for k, v in at["respuestas"].most_common())}')
        print(Color.c('90', '  Si alguna de estas IPs es de un proveedor o sede legítima, el problema es que la '
                            'centralita/firewall la está ignorando.'))

    if inf.terminales:
        titulo('Terminales (teléfonos registrados)')
        print(Color.c('1', f'  {"Ext.":6}  {"Dirección":21}  {"Modelo":26}  {"Resp. mediana":>13}  {"p90":>7}  OPTIONS'))
        for t in inf.terminales:
            med = f'{t["mediana"]:.0f} ms' if t['mediana'] is not None else '-'
            p90 = f'{t["p90"]:.0f} ms' if t['p90'] is not None else '-'
            col = '31' if t['peor'] == 3 else '33' if t['peor'] == 2 else ''
            print(f'  {Color.c(col, f"{corta(t["ext"], 6):6}") if col else f"{corta(t["ext"], 6):6}"}  {t["ep"]:21}  '
                  f'{corta(t["ua"], 26):26}  {med:>13}  {p90:>7}  {t.get("options", "-")}')
            for p in t['problemas']:
                if p[0] != 'ok':
                    linea_prob(p, '          ')

    if inf.registros:
        titulo('Registros (REGISTER)')
        for r in inf.registros:
            ult = r['ultimo']
            print(Color.c('1', f'  {r["aor"]}') + f'  desde {r["src"]} → {r["dst"]}   '
                  f'{r["total"]} envíos, {r["ok"]} OK, {r["retos"]} retos 401/407'
                  f'{", " + str(r["sin_resp"]) + " sin respuesta" if r["sin_resp"] else ""}   último: {ult}'
                  + (f'   expires {r["expires"]} s' if r['expires'] else ''))
            for p in r['problemas']:
                linea_prob(p, '     ')

    if inf.options:
        titulo('Keepalives OPTIONS')
        for g in inf.options:
            rtt = f'{g["rtt_med"]:.0f} ms' if g['rtt_med'] is not None else '-'
            print(Color.c('1', f'  {g["src"]} → {g["dst"]}') + Color.c('90', f'  {corta(g["uri"], 40)}') +
                  f'   {g["resp"]}/{g["total"]} respondidos   resp. media {rtt}   '
                  f'{", ".join(f"{k}×{v}" for k, v in g["codigos"].items())}')
            for p in g['problemas']:
                linea_prob(p, '     ')
    print()


def hosts_de(msgs):
    hosts = []
    for m in msgs:
        for h in (m.ep_src, m.ep_dst):
            if h not in hosts:
                hosts.append(h)
    return hosts


def escalera_txt(ll, completos):
    msgs = ll['msgs']
    hosts = hosts_de(msgs)
    rol = {ll['A']: 'LLAMANTE', ll['B']: 'LLAMADO'}
    W = 30 if len(hosts) <= 4 else 25
    if len(hosts) > 6:
        print(Color.c('90', '  (demasiados extremos para dibujar el diagrama; usa --html para verlo)'))
        for m in msgs:
            print(f'  {fmt_hora(m.ts)}  {m.ep_src:>21} → {m.ep_dst:21}  {m.etiqueta()}')
        return
    pos = {h: i * W + W // 2 for i, h in enumerate(hosts)}
    ancho = len(hosts) * W

    def cab(textos):
        l = [' '] * ancho
        for h, t in zip(hosts, textos):
            t = t[:W - 2]
            i = pos[h] - len(t) // 2
            l[i:i + len(t)] = t
        return ''.join(l)
    print(' ' * 14 + Color.c('1', cab([rol.get(h, '') for h in hosts])))
    print(' ' * 14 + Color.c('1', cab(hosts)))
    for m in msgs:
        l = [' '] * ancho
        for h in hosts:
            l[pos[h]] = '│'
        a, b = pos[m.ep_src], pos[m.ep_dst]
        et = m.etiqueta()
        if a != b:
            lo, hi = sorted((a, b))
            for x in range(lo + 1, hi):
                l[x] = '─'
            l[b - 1 if b > a else b + 1] = '▶' if b > a else '◀'
            et = et[:hi - lo - 3]
            ini = lo + 1 + (hi - lo - 1 - len(et)) // 2
            l[ini:ini + len(et)] = et
        else:
            et = ' ↺ ' + et
            l[a + 1:a + 1 + len(et)] = et[:ancho - a - 1]
        col = '90' if m.retrans else '34' if m.req else '32' if m.codigo < 300 and m.codigo >= 200 else '37' if m.codigo < 200 else '31'
        print(f'  {fmt_hora(m.ts)}' + Color.c(col, ''.join(l)[:ancho].rstrip()))
        if completos:
            for t in m.texto().rstrip().split('\n'):
                print(Color.c('90', ' ' * 16 + '┊ ' + t))


def imprimir_llamada(ll, completos):
    titulo(f'Llamada #{ll["n"]}')
    print(f'  Call-ID:     {ll["call_id"]}')
    print(f'  Llamante:    {ll["origen"]}' + (f' "{ll["nombre"]}"' if ll['nombre'] else '') + f'   ({ll["A"]})  {ll["ua_A"]}')
    print(f'  Llamado:     {ll["destino"]}' + (f'  (To: {ll["to"]})' if ll['to'] != ll['destino'] else '') + f'   ({ll["B"]})  {ll["ua_B"]}')
    print('  Estado:      ' + Color.c(color_estado(ll), ll['estado']) + f'   transporte {ll["transporte"]}')
    print(f'  Inicio:      {fmt_hora(ll["inicio"])}   Tono: {fmt_hora(ll["t_ring"])}   '
          f'Contesta: {fmt_hora(ll["t_resp"])}   Fin: {fmt_hora(ll["t_fin"])}')
    print(f'  Duración:    {fmt_dur(ll["duracion"])}' + (f'   colgó el {ll["colgo"]}' if ll['colgo'] else '')
          + (f'   códec {ll["codec"]}' if ll['codec'] else ''))
    if ll['problemas']:
        print(Color.c('1', '\n  Diagnóstico:'))
        for p in ll['problemas']:
            linea_prob(p, '   ')
    else:
        print('\n  ' + Color.c('32', '✔ Sin problemas detectados.'))
    if ll['rtp']:
        print(Color.c('1', '\n  Audio (RTP):'))
        for s in ll['rtp']:
            print(f'   {"→ llamante" if s["hacia"] == "A" else "→ llamado "}  {s["src"]}:{s["sport"]} → {s["dst"]}:{s["dport"]}  '
                  f'{s["codec"]}  {s["paquetes"]} paq.  pérdida {s["pct"]:.1f}%  jitter máx {s["jitter_max"]:.1f} ms  '
                  f'hueco máx {s["hueco"]:.0f} ms' + (f'  DTMF {s["dtmf"]}' if s['dtmf'] else ''))
    print(Color.c('1', '\n  Flujo SIP:'))
    escalera_txt(ll, completos)
    print()

# ───────────────────────────── Informe HTML ─────────────────────────────

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--tx:#1d1d1b;--mut:#6b6b66;--bd:#e2e1dc;--err:#c62828;--avi:#b26a00;--inf:#1565c0;--ok:#2e7d32;
--req:#1f5fbf;--prov:#8a8a85;--r2:#2e7d32;--rerr:#c62828;--retx:#b0b0aa;--hl:#fff7d6}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#161615;--card:#1f1f1d;--tx:#ecebe6;--mut:#9b9a94;--bd:#33322f;
--err:#ef6b6b;--avi:#f0a73a;--inf:#6aa9f0;--ok:#6cc070;--req:#7aa7ef;--prov:#8d8c86;--r2:#6cc070;--rerr:#ef6b6b;--retx:#5b5a56;--hl:#3a3420}}
:root[data-theme=dark]{color-scheme:dark;--bg:#161615;--card:#1f1f1d;--tx:#ecebe6;--mut:#9b9a94;--bd:#33322f;
--err:#ef6b6b;--avi:#f0a73a;--inf:#6aa9f0;--ok:#6cc070;--req:#7aa7ef;--prov:#8d8c86;--r2:#6cc070;--rerr:#ef6b6b;--retx:#5b5a56;--hl:#3a3420}
body{background:var(--bg);color:var(--tx);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:24px 16px 60px}
main{max-width:1200px;margin:0 auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--bd)}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 16px;margin:10px 0}
.kpis{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}.kpi{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 14px;min-width:110px}
.kpi b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.kpi span{color:var(--mut);font-size:12px}
.tw{overflow-x:auto}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--bd);white-space:nowrap}th{font-size:12px;color:var(--mut);font-weight:600}
tr.click{cursor:pointer}tr.click:hover td{background:var(--hl)}
.error{color:var(--err)}.aviso{color:var(--avi)}.info{color:var(--inf)}.ok{color:var(--ok)}
ul.p{list-style:none;padding:0;margin:6px 0}ul.p li{padding:3px 0 3px 22px;position:relative}
ul.p li:before{position:absolute;left:0;font-weight:700}ul.p li.error:before{content:"✖"}ul.p li.aviso:before{content:"⚠"}
ul.p li.info:before{content:"ℹ"}ul.p li.ok:before{content:"✔"}ul.p li{color:var(--tx)}ul.p li:before{color:inherit}
ul.p li.error:before{color:var(--err)}ul.p li.aviso:before{color:var(--avi)}ul.p li.info:before{color:var(--inf)}ul.p li.ok:before{color:var(--ok)}
details.ll{background:var(--card);border:1px solid var(--bd);border-radius:8px;margin:8px 0}
details.ll>summary{padding:10px 14px;cursor:pointer;font-weight:600}details.ll[open]>summary{border-bottom:1px solid var(--bd)}
.cuerpo{padding:10px 14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:4px 20px;margin-bottom:8px}
.grid div{overflow-wrap:anywhere}.grid b{color:var(--mut);font-weight:500;margin-right:6px}
svg.lad{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;display:block}
svg.lad .host{fill:var(--tx);font-weight:600}svg.lad .rol{fill:var(--mut)}svg.lad .vl{stroke:var(--bd);stroke-width:2}
svg.lad .t{fill:var(--mut)}svg.lad a:hover text{text-decoration:underline}
.k-req{stroke:var(--req);fill:var(--req)}.k-prov{stroke:var(--prov);fill:var(--prov)}.k-r2{stroke:var(--r2);fill:var(--r2)}
.k-rerr{stroke:var(--rerr);fill:var(--rerr)}.k-retx{stroke:var(--retx);fill:var(--retx)}
svg.lad line{stroke-width:1.6}svg.lad text.k-req,svg.lad text.k-prov,svg.lad text.k-r2,svg.lad text.k-rerr,svg.lad text.k-retx{stroke:none}
details.msg{border-top:1px solid var(--bd)}details.msg summary{padding:4px 0;cursor:pointer;font:12px ui-monospace,Menlo,monospace}
details.msg:target summary{background:var(--hl)}pre{margin:4px 0 10px;padding:10px;background:var(--bg);border-radius:6px;overflow-x:auto;font:12px/1.4 ui-monospace,Menlo,monospace}
.estado-ok{color:var(--ok)}a{color:var(--inf)}.estado-can{color:var(--inf)}.estado-ko{color:var(--err)}
"""

JS = """
function abrir(){var h=location.hash.slice(1);if(!h)return;var e=document.getElementById(h);if(!e)return;
for(var p=e;p;p=p.parentElement){if(p.tagName==='DETAILS')p.open=true;}e.scrollIntoView({block:'start'});}
addEventListener('hashchange',abrir);addEventListener('DOMContentLoaded',abrir);
"""


def esc(s):
    return html.escape(str(s if s is not None else ''))


def lista_prob(problemas):
    return '<ul class="p">' + ''.join(f'<li class="{p[0]}">{esc(p[1])}</li>' for p in problemas) + '</ul>'


def clase_msg(m):
    if m.retrans:
        return 'k-retx'
    if m.req:
        return 'k-req'
    return 'k-prov' if m.codigo < 200 else 'k-r2' if m.codigo < 300 else 'k-rerr'


def svg_escalera(ll):
    msgs = ll['msgs']
    hosts = hosts_de(msgs)
    rol = {ll['A']: 'LLAMANTE', ll['B']: 'LLAMADO'}
    X0, W, RH, TOP = 110, 220, 24, 52
    xs = {h: X0 + i * W for i, h in enumerate(hosts)}
    ancho = X0 + W * (len(hosts) - 1) + 130
    alto = TOP + RH * len(msgs) + 16
    o = [f'<svg class="lad" width="{ancho}" height="{alto}" viewBox="0 0 {ancho} {alto}">']
    for h in hosts:
        x = xs[h]
        o.append(f'<text class="rol" x="{x}" y="16" text-anchor="middle">{rol.get(h, "")}</text>'
                 f'<text class="host" x="{x}" y="34" text-anchor="middle">{esc(h)}</text>'
                 f'<line class="vl" x1="{x}" y1="42" x2="{x}" y2="{alto - 6}"/>')
    for k, m in enumerate(msgs):
        y = TOP + RH * k + 14
        a, b = xs[m.ep_src], xs[m.ep_dst]
        c = clase_msg(m)
        o.append(f'<a href="#ll{ll["n"]}m{k}"><title>{esc(m.src)}:{m.sport} → {esc(m.dst)}:{m.dport} {m.transporte}</title>'
                 f'<text class="t" x="6" y="{y + 4}">{fmt_hora(m.ts)}</text>')
        if a != b:
            d = 1 if b > a else -1
            o.append(f'<line class="{c}" x1="{a}" y1="{y}" x2="{b - d * 2}" y2="{y}"/>'
                     f'<path class="{c}" d="M{b} {y} l{-d * 8} -4 v8 z"/>'
                     f'<text class="{c}" x="{(a + b) / 2}" y="{y - 4}" text-anchor="middle">{esc(corta(m.etiqueta(), 32))}</text>')
        else:
            o.append(f'<text class="{c}" x="{a + 8}" y="{y + 4}">↺ {esc(m.etiqueta())}</text>')
        o.append('</a>')
    o.append('</svg>')
    return ''.join(o)


def html_llamada(ll):
    e, a = contar(ll['problemas'])
    marca = (f' <span class="error">✖{e}</span>' if e else '') + (f' <span class="aviso">⚠{a}</span>' if a else '')
    est = 'estado-ok' if ll['estado'].startswith('Contestada') else 'estado-can' if ll['estado'] == 'Cancelada' else 'estado-ko'
    o = [f'<details class="ll" id="llamada{ll["n"]}"><summary>#{ll["n"]} · {fmt_hora(ll["inicio"])} · '
         f'{esc(ll["origen"])} → {esc(ll["destino"])} · <span class="{est}">{esc(ll["estado"])}</span>{marca}</summary><div class="cuerpo">']
    datos = [('Call-ID', ll['call_id']), ('Llamante', f'{ll["origen"]} {ll["nombre"]} ({ll["A"]})'),
             ('Llamado', f'{ll["destino"]} ({ll["B"]})'), ('To', ll['to']),
             ('UA llamante', ll['ua_A']), ('UA llamado', ll['ua_B']),
             ('Inicio', fmt_hora(ll['inicio'])), ('Tono', fmt_hora(ll['t_ring'])),
             ('Contesta', fmt_hora(ll['t_resp'])), ('Fin', fmt_hora(ll['t_fin'])),
             ('Duración', fmt_dur(ll['duracion']) + (f' · colgó el {ll["colgo"]}' if ll['colgo'] else '')),
             ('Códec', ll['codec'] or '-'), ('Transporte', ll['transporte'])]
    o.append('<div class="grid">' + ''.join(f'<div><b>{k}</b>{esc(v)}</div>' for k, v in datos if v) + '</div>')
    o.append(lista_prob(ll['problemas']) if ll['problemas'] else '<ul class="p"><li class="ok">Sin problemas detectados.</li></ul>')
    if ll['rtp']:
        o.append('<div class="tw"><table><tr><th>Sentido</th><th>Origen</th><th>Destino</th><th>Códec</th><th>Paquetes</th>'
                 '<th>Pérdida</th><th>Jitter máx</th><th>Hueco máx</th><th>DTMF</th></tr>')
        for s in ll['rtp']:
            o.append(f'<tr><td>→ {"llamante" if s["hacia"] == "A" else "llamado"}</td><td>{esc(s["src"])}:{s["sport"]}</td>'
                     f'<td>{esc(s["dst"])}:{s["dport"]}</td><td>{esc(s["codec"])}</td><td>{s["paquetes"]}</td>'
                     f'<td>{s["pct"]:.1f}%</td><td>{s["jitter_max"]:.1f} ms</td><td>{s["hueco"]:.0f} ms</td><td>{s["dtmf"]}</td></tr>')
        o.append('</table></div>')
    o.append('<h3 style="font-size:14px;margin:16px 0 6px">Flujo SIP <span class="mut">(clic en un mensaje para ver su contenido)</span></h3>')
    o.append(f'<div class="tw">{svg_escalera(ll)}</div>')
    for k, m in enumerate(ll['msgs']):
        o.append(f'<details class="msg" id="ll{ll["n"]}m{k}"><summary>{fmt_hora(m.ts)} {esc(m.src)}:{m.sport} → '
                 f'{esc(m.dst)}:{m.dport} {m.transporte} · {esc(m.etiqueta())}</summary><pre>{esc(m.texto())}</pre></details>')
    o.append('</div></details>')
    return ''.join(o)


def generar_html(inf, llamadas):
    cap = inf.cap
    nombre = os.path.basename(cap.path)
    err = sum(contar(ll['problemas'])[0] > 0 for ll in inf.llamadas if not ll['escaneo'])
    contestadas = sum(ll['estado'].startswith('Contestada') for ll in inf.llamadas)
    o = [f'<title>sipcap · {esc(nombre)}</title><style>{CSS}</style><main>',
         f'<h1>Análisis SIP · {esc(nombre)}</h1>']
    if cap.t0:
        o.append(f'<div class="mut">{datetime.fromtimestamp(cap.t0):%d/%m/%Y %H:%M:%S} → '
                 f'{datetime.fromtimestamp(cap.t1):%H:%M:%S} ({fmt_dur(cap.t1 - cap.t0)}) · {cap.n} paquetes · '
                 f'{len(cap.sip)} mensajes SIP · generado {datetime.now():%d/%m/%Y %H:%M}</div>')
    kp = [('Llamadas', len(inf.llamadas)), ('Contestadas', contestadas), ('Con errores', err),
          ('Escaneos', sum(at['llamadas'] for at in inf.ataques)),
          ('Registros', len(inf.registros)), ('OPTIONS', len(inf.options)), ('Flujos RTP', len(inf.flujos))]
    o.append('<div class="kpis">' + ''.join(f'<div class="kpi"><b>{v}</b><span>{k}</span></div>' for k, v in kp) + '</div>')
    if inf.notas or inf.errores:
        o.append('<div class="card">' + lista_prob([('info', n) for n in inf.notas]))
        if inf.errores:
            o.append('<div class="mut">Respuestas de error: ' + esc(', '.join(f'{v}× {k}' for k, v in inf.errores.most_common(10))) + '</div>')
        o.append('</div>')

    averias = agrupar_averias(llamadas, inf.options)
    if averias:
        o.append('<h2>Resumen de averías</h2><div class="card"><ul class="p">')
        for txt, av in averias:
            refs = ' '.join(f'<a href="#llamada{x}">#{x}</a>' for x in av['llamadas'][:15]) + (' …' if len(av['llamadas']) > 15 else '')
            o.append(f'<li class="{av["nivel"]}">{esc(txt)} <span class="mut">· {len(av["llamadas"])} llamada(s): {refs}</span>'
                     + (f'<br><span class="mut">↳ {esc(av["extra"])}</span>' if av.get('extra') else '') + '</li>')
        o.append('</ul></div>')
    if inf.bajas:
        o.append('<h2>Extensiones sin registro</h2>')
        for b in inf.bajas:
            fin = fmt_hora(b['fin']) if b['fin'] else 'fin de la captura'
            refs = ' '.join(f'<a href="#llamada{x}">#{x}</a>' for x in b['llamadas'])
            o.append(f'<div class="card"><b class="{b["nivel"]}">Ext. {esc(b["ext"])}</b> · sin registro de '
                     f'{fmt_hora(b["inicio"])} a {fin} ({fmt_dur(b["duracion"])})<div>{esc(b["texto"])}</div>'
                     + (f'<div class="error">Llamadas que no le llegaron: {refs}</div>' if refs else '') + '</div>')
    o.append(f'<h2>Llamadas ({len(llamadas)})</h2>')
    if llamadas:
        o.append('<div class="tw"><table><tr><th>#</th><th>Hora</th><th>Origen</th><th>Destino</th><th>Estado</th>'
                 '<th>Duración</th><th>Códec</th><th>Problemas</th></tr>')
        for ll in llamadas:
            e, a = contar(ll['problemas'])
            pr = (f'<span class="error">✖ {e}</span> ' if e else '') + (f'<span class="aviso">⚠ {a}</span>' if a else '') or '<span class="ok">✔</span>'
            est = 'estado-ok' if ll['estado'].startswith('Contestada') else 'estado-can' if ll['estado'] == 'Cancelada' else 'estado-ko'
            o.append(f'<tr class="click" onclick="location.hash=\'llamada{ll["n"]}\'"><td>{ll["n"]}</td><td>{fmt_hora(ll["inicio"])}</td>'
                     f'<td>{esc(corta(ll["origen"], 24))}</td><td>{esc(corta(ll["destino"], 24))}</td>'
                     f'<td class="{est}">{esc(ll["estado"])}</td><td>{fmt_dur(ll["duracion"])}</td><td>{esc(ll["codec"])}</td><td>{pr}</td></tr>')
        o.append('</table></div>')
        o.append('<h2>Detalle de llamadas</h2>')
        o.extend(html_llamada(ll) for ll in llamadas)
    else:
        o.append('<p class="mut">No hay llamadas.</p>')

    if inf.ataques:
        o.append('<h2>Intentos sospechosos (escaneos / fraude)</h2><div class="tw"><table><tr><th>IP</th><th>INVITE</th>'
                 '<th>Periodo</th><th>User-Agent</th><th>Destinos</th><th>Respuesta</th></tr>')
        for at in inf.ataques:
            o.append(f'<tr><td class="{"error" if at["exito"] else "aviso"}">{esc(at["ip"])}'
                     + (' ¡CONTESTADA!' if at['exito'] else '') + f'</td><td>{at["llamadas"]}</td>'
                     f'<td>{fmt_hora(at["inicio"])}–{fmt_hora(at["fin"])}</td>'
                     f'<td style="white-space:normal">{esc(", ".join(u or "(vacío)" for u in at["uas"]))}</td>'
                     f'<td style="white-space:normal">{esc(", ".join(list(at["destinos"])[:6]))}</td>'
                     f'<td>{esc(", ".join(f"{k} ×{v}" for k, v in at["respuestas"].items()))}</td></tr>')
        o.append('</table></div>')
    if inf.terminales:
        o.append('<h2>Terminales (teléfonos registrados)</h2><div class="tw"><table><tr><th>Ext.</th><th>Dirección</th>'
                 '<th>Modelo</th><th>Resp. mediana</th><th>p90</th><th>OPTIONS</th><th>Diagnóstico</th></tr>')
        for t in inf.terminales:
            med = f'{t["mediana"]:.0f} ms' if t['mediana'] is not None else '-'
            p90 = f'{t["p90"]:.0f} ms' if t['p90'] is not None else '-'
            o.append(f'<tr><td><b>{esc(t["ext"])}</b></td><td>{esc(t["ep"])}</td><td>{esc(t["ua"])}</td><td>{med}</td>'
                     f'<td>{p90}</td><td>{esc(t.get("options", "-"))}</td>'
                     f'<td style="white-space:normal;min-width:320px">{lista_prob(t["problemas"])}</td></tr>')
        o.append('</table></div>')
    if inf.registros:
        o.append('<h2>Registros (REGISTER)</h2>')
        for r in inf.registros:
            o.append(f'<div class="card"><b>{esc(r["aor"])}</b> <span class="mut">desde {esc(r["src"])} → {esc(r["dst"])} · '
                     f'{esc(r["ua"])}</span><div>{r["total"]} envíos · {r["ok"]} OK · {r["retos"]} retos 401/407 · '
                     f'{r["sin_resp"]} sin respuesta · último: {esc(r["ultimo"])}'
                     + (f' · expires {r["expires"]} s' if r['expires'] else '') + '</div>' + lista_prob(r['problemas']) + '</div>')
    if inf.options:
        o.append('<h2>Keepalives OPTIONS</h2><div class="tw"><table><tr><th>Origen</th><th>Destino</th><th>URI</th><th>Respondidos</th>'
                 '<th>Resp. media</th><th>Códigos</th><th>Diagnóstico</th></tr>')
        for g in inf.options:
            rtt = f'{g["rtt_med"]:.0f} ms' if g['rtt_med'] is not None else '-'
            o.append(f'<tr><td>{esc(g["src"])}</td><td>{esc(g["dst"])}</td><td>{esc(corta(g["uri"], 40))}</td>'
                     f'<td>{g["resp"]}/{g["total"]}</td><td>{rtt}</td>'
                     f'<td>{esc(", ".join(f"{k}×{v}" for k, v in g["codigos"].items()))}</td>'
                     f'<td style="white-space:normal">{lista_prob(g["problemas"])}</td></tr>')
        o.append('</table></div>')
    o.append(f'</main><script>{JS}</script>')
    return '\n'.join(o)

# ───────────────────────────── Programa principal ─────────────────────────────


def main():
    ap = argparse.ArgumentParser(prog='sipcap', description=__doc__.split('\n\n')[0].strip(),
                                 epilog=__doc__.split('\n\n', 1)[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('captura', help='fichero .pcap / .pcapng (puede estar comprimido con gzip)')
    ap.add_argument('-l', '--llamada', type=int, metavar='N', help='muestra el detalle y el diagrama de la llamada N')
    ap.add_argument('-m', '--mensajes', action='store_true', help='con -l, muestra el texto completo de cada mensaje SIP')
    ap.add_argument('-n', '--numero', help='solo llamadas en las que aparece este número/usuario')
    ap.add_argument('-p', '--problemas', action='store_true', help='solo llamadas con errores o avisos')
    ap.add_argument('-a', '--ataques', action='store_true', help='incluye en la lista los intentos de escaneo/ataque')
    ap.add_argument('--html', nargs='?', const='', metavar='FICHERO', help='genera un informe HTML (por defecto junto a la captura)')
    ap.add_argument('--no-abrir', action='store_true', help='no abrir el informe HTML en el navegador')
    ap.add_argument('--sin-color', action='store_true', help='desactiva los colores en la terminal')
    a = ap.parse_args()
    if a.sin_color:
        Color.activo = False

    try:
        cap = Captura(a.captura)
    except FileNotFoundError:
        sys.exit(f'No existe el fichero: {a.captura}')
    except (ValueError, OSError, EOFError) as e:
        sys.exit(f'No se puede leer {a.captura}: {e}')
    inf = Informe(cap)
    llamadas = filtrar(inf.llamadas, a.numero, a.problemas, a.ataques)

    if a.llamada:
        ll = next((x for x in inf.llamadas if x['n'] == a.llamada), None)
        if not ll:
            sys.exit(f'No existe la llamada #{a.llamada} (hay {len(inf.llamadas)}).')
        imprimir_llamada(ll, a.mensajes)
    else:
        imprimir_resumen(inf, llamadas, a.problemas or bool(a.numero))

    if a.html is not None:
        destino = a.html or os.path.splitext(a.captura)[0] + '_informe.html'
        with open(destino, 'w', encoding='utf-8') as f:
            f.write('<!doctype html><html lang="es"><head><meta charset="utf-8">'
                    '<meta name="viewport" content="width=device-width,initial-scale=1">')
            f.write(generar_html(inf, llamadas).replace('<main>', '</head><body><main>', 1))
            f.write('</body></html>')
        print(f'Informe HTML: {destino}')
        if not a.no_abrir:
            webbrowser.open('file://' + os.path.abspath(destino))


if __name__ == '__main__':
    try:
        main()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
