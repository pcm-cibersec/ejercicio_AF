#!/usr/bin/env python3
"""General-purpose PCAP/PCAPNG summary and HTTP packet inspector."""
from __future__ import annotations
import argparse
import asyncio
import ipaddress
import re
import sys
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# Considera grande una carga útil de al menos 10 KiB.
UPLOAD_MIN_BYTES = 10 * 1024
GET_LONG_URI_CHARS = 250
GET_LONG_QUERY_CHARS = 200

# PyShark interpreta la captura mediante TShark; si no está instalado,
# guardamos el estado para mostrar un mensaje claro al iniciar el análisis.
try:
    import pyshark
except ImportError:
    pyshark = None


def field_value(layer: Any, *names: str) -> str | None:
    """Busca un campo de una capa probando varios nombres compatibles."""
    if layer is None:
        return None
    for name in names:
        # Primero se consulta la interfaz de campos de PyShark.
        try:
            value = layer.get_field_value(name)
            if value is not None and str(value).strip():
                return str(value).strip()
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
        # Como alternativa, se intenta acceder al campo como atributo.
        try:
            value = getattr(layer, name)
            if value is not None and str(value).strip():
                return str(value).strip()
        except (AttributeError, KeyError, TypeError, ValueError):
            pass
    return None


def packet_layer(packet: Any, *names: str) -> Any | None:
    """Obtiene una capa del paquete, probando nombres alternativos."""
    for name in names:
        try:
            if name in packet:
                return packet[name]
        except (AttributeError, KeyError, TypeError):
            pass
        try:
            return getattr(packet, name)
        except (AttributeError, KeyError, TypeError):
            pass
    return None


def packet_ips(packet: Any) -> tuple[str, str]:
    # Admite IPv4 e IPv6 y sustituye los campos ausentes por un marcador.
    ip = packet_layer(packet, "ip", "ipv6")
    return (field_value(ip, "src") or "(desconocida)",
            field_value(ip, "dst") or "(desconocida)")


def packet_protocols(packet: Any) -> set[str]:
    # Devuelve las capas presentes, sin duplicar un protocolo dentro del paquete.
    try:
        layers = packet.layers
    except AttributeError:
        return set()
    return {str(layer.layer_name).upper() for layer in layers
            if getattr(layer, "layer_name", None)}


def packet_time(packet: Any) -> float | None:
    # Convierte la marca temporal a segundos para calcular la duración.
    try:
        return float(packet.sniff_timestamp)
    except (AttributeError, TypeError, ValueError):
        return None


def tcp_packet_info(packet: Any) -> tuple[tuple[tuple[str, str], tuple[str, str]], tuple[str, str], tuple[str, str], int] | None:
    """Devuelve el flujo TCP, sus extremos y los bytes de payload del segmento."""
    tcp = packet_layer(packet, "tcp")
    if tcp is None:
        return None
    src_ip, dst_ip = packet_ips(packet)
    src_port = field_value(tcp, "srcport")
    dst_port = field_value(tcp, "dstport")
    tcp_length = field_value(tcp, "len")
    if not src_port or not dst_port or tcp_length is None:
        return None
    try:
        length = int(tcp_length)
    except (TypeError, ValueError):
        return None
    src, dst = (src_ip, src_port), (dst_ip, dst_port)
    first, second = sorted((src, dst))
    return (first, second), src, dst, length


def http_details(packet: Any) -> dict[str, Any] | None:
    """Extrae los campos de HTTP y clasifica el paquete como petición o respuesta."""
    http = packet_layer(packet, "http")
    if http is None:
        return None
    # La presencia del método identifica peticiones; el código identifica respuestas.
    method = field_value(http, "request_method")
    code = field_value(http, "response_code")
    is_request, is_response = method is not None, code is not None
    kind = ("Petición HTTP" if is_request else "Respuesta HTTP" if is_response
            else "HTTP (sin clasificar)")
    host = field_value(http, "host") or "(no disponible)"
    uri = field_value(http, "request_full_uri", "request_uri") or "(no disponible)"
    agent = field_value(http, "user_agent") or "(no disponible)"
    # TShark puede exponer el cuerpo reensamblado en el campo file_data.
    body = field_value(http, "file_data")
    body_bytes: bytes | None = None
    if body and body.lower().startswith("0x"):
        try:
            body_bytes = bytes.fromhex(body[2:])
            body = body_bytes.decode("utf-8", errors="replace")
        except ValueError:
            pass
    # Resume el cuerpo con su tipo y tamaño; la vista previa es opcional.
    content_type = field_value(http, "content_type")
    declared_length = field_value(http, "content_length")
    body_size = 0
    if body:
        body_size = len(body_bytes) if body_bytes is not None else len(body.encode("utf-8"))
        size_text = f"{body_size} bytes (observados)"
    elif declared_length:
        try:
            body_size = int(declared_length)
        except ValueError:
            body_size = 0
        size_text = f"{declared_length} bytes (declarados)"
    else:
        size_text = "tamaño no disponible"
    content_summary = f"{content_type or 'tipo no identificado'}, {size_text}"
    if is_request and method.upper() == "POST" and not body and not declared_length:
        content_summary = "body no disponible en esta captura"
    body_preview = body or ""
    label = method or (f"{code} {field_value(http, 'response_phrase') or ''}".strip())
    return {
        "kind": kind,
        "label": label or "(no disponible)",
        "host": host,
        "uri": uri,
        "user_agent": agent,
        "content_summary": content_summary,
        "body_preview": body_preview,
        "status_code": code or "",
        "body_size": body_size,
    }


def get_query_reasons(uri: str) -> list[str]:
    """Devuelve los indicadores de URI larga o query codificada detectados en un GET."""
    try:
        query = urlsplit(uri).query
    except ValueError:
        query = uri.partition("?")[2]
    reasons: list[str] = []
    if len(uri) >= GET_LONG_URI_CHARS:
        reasons.append(f"URI larga ({len(uri)} caracteres)")
    if len(query) >= GET_LONG_QUERY_CHARS:
        reasons.append(f"query larga ({len(query)} caracteres)")

    # Comprueba valores con nombre y elementos sin nombre. Una cadena Base64
    # puede incluir «=» solo como relleno y perderse si se trata como clave=valor.
    candidates: list[str] = []
    for parameter in re.split(r"[&;]", query):
        _key, separator, value = parameter.partition("=")
        if separator and value:
            candidates.append(value)
            if value.strip("=") == "":
                candidates.append(parameter)
        else:
            candidates.append(parameter)

    for value in candidates:
        escapes = len(re.findall(r"%[0-9a-fA-F]{2}", value))
        if escapes >= 3 and (3 * escapes / len(value)) >= 0.20:
            reasons.append("parámetro con codificación URL (%xx)")
            break

    # Un valor largo compatible con Base64 puede transportar datos o ser un token.
    if any(re.fullmatch(r"[A-Za-z0-9+/_-]{40,}={0,2}", value) for value in candidates):
        reasons.append("parámetro largo compatible con Base64")
    return reasons


def suspicious_host_reason(host: str) -> str | None:
    """Returns why a Host is notable, or None when it does not match the heuristic."""
    if not host or host == "(no disponible)":
        return "Host ausente"
    try:
        hostname = urlsplit(f"//{host.strip()}").hostname
    except ValueError:
        hostname = None
    if not hostname:
        return None
    hostname = hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(hostname)
        return "Host formado por una dirección IP"
    except ValueError:
        pass
    labels = hostname.split(".")
    subdomains = labels[:-2] if len(labels) > 2 else []
    if len(hostname) >= 100 or any(len(label) >= 30 for label in subdomains):
        return "Subdominio inusualmente largo"
    if len(subdomains) >= 3:
        return f"Muchos niveles de subdominio ({len(subdomains)})"
    return None


def analyze(path: Path, show_content: bool = False,
            methods_only: bool = False, show_ips: bool = False,
            upload_only: bool = False, get_only: bool = False,
            host_only: bool = False, show_volume: bool = False) -> int:
    """Lee toda la captura, reúne estadísticas y presenta los paquetes HTTP."""
    if pyshark is None:
        print("Error: falta PyShark. Instálalo con: python -m pip install pyshark", file=sys.stderr)
        return 2
    if not path.is_file():
        print(f"Error: no existe el archivo: {path}", file=sys.stderr)
        return 2
    # Acumuladores para el resumen general y las filas HTTP de la salida.
    total, protocol_counts = 0, Counter()
    times: list[float] = []
    http_items: list[tuple[str, str, float | None, dict[str, Any]]] = []
    tcp_flows: dict[Any, dict[str, Any]] = {}
    host_request_counts: Counter[str] = Counter()
    host_destinations: dict[str, set[str]] = defaultdict(set)
    try:
        # Python reciente ya no crea este bucle automáticamente; PyShark lo usa
        # para comunicarse de forma asíncrona con el proceso TShark.
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
        # keep_packets=False evita conservar en memoria toda la captura.
        capture = pyshark.FileCapture(str(path), keep_packets=False)
        try:
            # Recorre cada paquete una vez y conserva solo los datos necesarios.
            for packet in capture:
                total += 1
                protocol_counts.update(packet_protocols(packet))
                timestamp = packet_time(packet)
                if timestamp is not None:
                    times.append(timestamp)
                # Acumula tamaños TCP por flujo para estimar el volumen en ambas direcciones.
                flow_info = tcp_packet_info(packet)
                if flow_info:
                    flow_key, src_endpoint, dst_endpoint, frame_length = flow_info
                    first, _second = flow_key
                    flow = tcp_flows.setdefault(flow_key, {
                        "bytes_first_to_second": 0,
                        "bytes_second_to_first": 0,
                        "client_endpoint": None,
                        "server_endpoint": None,
                        "hosts": set(),
                    })
                    direction = "bytes_first_to_second" if src_endpoint == first else "bytes_second_to_first"
                    flow[direction] += frame_length
                details = http_details(packet)
                if details:
                    # Registra el Host y destino de cada petición, aunque otros filtros oculten su fila.
                    if details["kind"] == "Petición HTTP":
                        request_host = details["host"]
                        _src_ip, request_dst_ip = packet_ips(packet)
                        host_request_counts[request_host] += 1
                        host_destinations[request_host].add(request_dst_ip)
                        if flow_info:
                            flow = tcp_flows[flow_info[0]]
                            if request_host != "(no disponible)":
                                flow["hosts"].add(request_host)
                            if flow["server_endpoint"] is None:
                                flow["client_endpoint"] = flow_info[1]
                                flow["server_endpoint"] = flow_info[2]
                    # --upload conserva solo peticiones de subida con cuerpo grande.
                    if upload_only and (
                        details["kind"] != "Petición HTTP"
                        or details["label"].upper() not in {"POST", "PUT", "PATCH"}
                        or details["body_size"] < UPLOAD_MIN_BYTES
                    ):
                        continue
                    # --GET selecciona GET con query larga o cadenas codificadas.
                    if get_only:
                        if details["kind"] != "Petición HTTP" or details["label"].upper() != "GET":
                            continue
                        reasons = get_query_reasons(details["uri"])
                        if not reasons:
                            continue
                        details["get_reasons"] = reasons
                    # --host solo evalúa encabezados Host de peticiones HTTP.
                    if host_only:
                        if details["kind"] != "Petición HTTP":
                            continue
                        reason = suspicious_host_reason(details["host"])
                        if reason is None:
                            continue
                        details["host_reason"] = reason
                    # Con -m se conservan solo las peticiones que tienen método HTTP.
                    if methods_only and details["kind"] != "Petición HTTP":
                        continue
                    # Las respuestas 204 no contienen cuerpo y se omiten del detalle HTTP.
                    if details["status_code"] == "204":
                        continue
                    # Los paquetes HTTP sin método de petición ni código de respuesta no son filas útiles.
                    if details["kind"] == "HTTP (sin clasificar)":
                        continue
                    src, dst = packet_ips(packet)
                    http_items.append((src, dst, timestamp, details))
        finally:
            # Cierra TShark incluso si el recorrido encuentra un error.
            capture.close()
    except Exception as exc:
        print(f"Error al leer la captura: {exc}", file=sys.stderr)
        print("Comprueba que Wireshark/TShark esté instalado y disponible en PATH.", file=sys.stderr)
        return 1
    # Presenta el resumen general antes del detalle de las comunicaciones HTTP.
    print("=== RESUMEN DE LA CAPTURA ===")
    print(f"Archivo: {path}\nPaquetes totales: {total}")
    print("Protocolos (paquetes que contienen cada protocolo):")
    if protocol_counts:
        for protocol, count in sorted(protocol_counts.items(), key=lambda item: (-item[1], item[0])):
            print(f"  {protocol}: {count}")
    else:
        print("  (no disponibles)")
    if times:
        print(f"Duración: {timedelta(seconds=round(max(times) - min(times), 3))}")
    else:
        print("Duración: (marcas de tiempo no disponibles)")

    print("\n=== PAQUETES HTTP ===")
    if not http_items:
        print("No se encontraron paquetes HTTP decodificados en la captura.")
    else:
        # Presenta cada mensaje HTTP con los campos disponibles en la captura.
        for index, (src, dst, timestamp, details) in enumerate(http_items, 1):
            time_text = f" | tiempo {timestamp:.6f}" if timestamp is not None else ""
            print(f"\n[{index}] {details['kind']}{time_text}")
            print(f"  Flujo: {src} -> {dst}\n  Host: {details['host']}")
            if details.get("get_reasons"):
                print(f"  Motivo del filtro --GET: {', '.join(details['get_reasons'])}")
            if details.get("host_reason"):
                print(f"  Motivo del filtro --host: {details['host_reason']}")
            print(f"  Método/estado: {details['label']}\n  URI: {details['uri']}")
            print(f"  User-Agent: {details['user_agent']}")
            if (details["body_preview"]
                    or details["label"].upper() in {"POST", "PUT", "PATCH"}):
                print(f"  Contenido: {details['content_summary']}")
                # Evita que un body extenso inunde la terminal incluso al solicitarlo.
                if show_content and details["body_preview"]:
                    preview = details["body_preview"]
                    limit = 500
                    if len(preview) > limit:
                        preview = preview[:limit] + "… (vista previa truncada)"
                    print(f"  Vista previa del body: {preview}")

    # El informe agrupa endpoints HTTP y asocia el Host a la IP destino de la petición.
    if show_ips:
        ip_directions: dict[str, set[str]] = defaultdict(set)
        ip_hosts: dict[str, set[str]] = defaultdict(set)
        for src, dst, _timestamp, details in http_items:
            ip_directions[src].add("origen")
            ip_directions[dst].add("destino")
            host = details["host"]
            if details["kind"] == "Petición HTTP" and host != "(no disponible)":
                ip_hosts[dst].add(host)
        print("\n=== IPs EN COMUNICACIONES HTTP ===")
        for address in sorted(ip_directions):
            hosts = ", ".join(sorted(ip_hosts[address])) or "(Host no observado)"
            directions = "/".join(sorted(ip_directions[address]))
            print(f"{address} [{directions}] — Host: {hosts}")

    if show_volume:
        print("\n=== PETICIONES POR HOST ===")
        if host_request_counts:
            for host, count in sorted(host_request_counts.items(), key=lambda item: (-item[1], item[0])):
                destinations = ", ".join(sorted(host_destinations[host]))
                print(f"{host}: {count} peticiones | IP destino(s): {destinations}")
        else:
            print("No se encontraron peticiones HTTP.")

        # Agrupa el payload TCP de flujos HTTP por IP servidor.
        volume_by_ip: dict[str, dict[str, Any]] = {}
        for flow_key, flow in tcp_flows.items():
            server = flow["server_endpoint"]
            client = flow["client_endpoint"]
            if server is None or client is None:
                continue
            first, _second = flow_key
            if client == first:
                sent = flow["bytes_first_to_second"]
                received = flow["bytes_second_to_first"]
            else:
                sent = flow["bytes_second_to_first"]
                received = flow["bytes_first_to_second"]
            address = server[0]
            totals = volume_by_ip.setdefault(address, {
                "sent": 0, "received": 0, "hosts": set(),
            })
            totals["sent"] += sent
            totals["received"] += received
            totals["hosts"].update(flow["hosts"])

        print("\n=== VOLUMEN DE DATOS TCP POR IP DESTINO HTTP ===")
        if volume_by_ip:
            for address, totals in sorted(volume_by_ip.items(),
                                          key=lambda item: (-item[1]["sent"], item[0])):
                sent, received = totals["sent"], totals["received"]
                ratio = f"{sent / received:.2f}:1" if received else ("infinita" if sent else "0.00:1")
                hosts = ", ".join(sorted(totals["hosts"])) or "(Host no observado)"
                print(f"{address} | Host(s): {hosts} | Payload saliente: {sent:,} B | "
                      f"Payload entrante: {received:,} B | Salida/entrada: {ratio}")
        else:
            print("No se pudieron asociar flujos TCP a peticiones HTTP.")

    # Cierra con el contador de filas HTTP y el resumen general de la captura.
    request_count = sum(item[3]["kind"] == "Petición HTTP" for item in http_items)
    response_count = sum(item[3]["kind"] == "Respuesta HTTP" for item in http_items)
    print(f"\nPeticiones HTTP mostradas: {request_count}")
    if not methods_only:
        print(f"Respuestas HTTP mostradas: {response_count}")
    return 0


def main() -> int:
    # Define la interfaz de línea de comandos y obtiene la ruta del PCAP.
    parser = argparse.ArgumentParser(description="Resume una captura PCAP/PCAPNG y muestra HTTP decodificado.")
    parser.add_argument("capture", type=Path, help="archivo .pcap, .pcapng o .cap")
    parser.add_argument("--content", action="store_true",
                        help="muestra hasta 500 caracteres del body HTTP disponible")
    parser.add_argument("-m", action="store_true", dest="methods_only",
                        help="muestra solo peticiones con método HTTP y filtra las respuestas")
    parser.add_argument("--ip", action="store_true",
                        help="muestra las IPs únicas de HTTP y el Host asociado cuando se conoce")
    parser.add_argument("--volume", action="store_true",
                        help="resume peticiones por Host y bytes TCP por IP destino HTTP")
    filters = parser.add_mutually_exclusive_group()
    filters.add_argument("--POST", action="store_true",
                         help="filtra POST, PUT y PATCH con cuerpos de al menos 10 KiB")
    filters.add_argument("--GET", action="store_true", dest="get_only",
                         help="filtra GET con URI/query larga o parámetros URL/Base64 codificados")
    parser.add_argument("--host", action="store_true", dest="host_only",
                        help="filtra peticiones con Host ausente, IP literal o subdominio largo")
    args = parser.parse_args()
    return analyze(args.capture, args.content, args.methods_only,
                   args.ip, args.POST, args.get_only, args.host_only, args.volume)


if __name__ == "__main__":
    # Permite usar el archivo como programa y devolver su código de salida.
    raise SystemExit(main())
