#!/usr/bin/env python3
import socket
import argparse
import concurrent.futures
import time
from datetime import datetime
from typing import List, Tuple


def scan_tcp_port(target: str, port: int, timeout: float) -> Tuple[int, str]:
    """Tenta conectar via TCP. Retorna (porta, status)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                return port, 'open'
            else:
                return port, 'closed'
    except Exception:
        return port, 'error'


def scan_udp_port(target: str, port: int, timeout: float) -> Tuple[int, str]:
    """Envia um pacote UDP e aguarda resposta. Se não houver resposta -> open|filtered.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # envia um payload pequeno
            try:
                s.sendto(b"\x00", (target, port))
            except Exception:
                return port, 'error'

            try:
                data, _ = s.recvfrom(4096)
                if data:
                    return port, 'open'  # recebeu resposta UDP -> provavelmente aberto
                else:
                    return port, 'open|filtered'
            except socket.timeout:
                return port, 'open|filtered'
            except Exception:
                return port, 'error'
    except Exception:
        return port, 'error'


def parse_port_range(start: int, end: int) -> List[int]:
    if start < 1:
        start = 1
    if end > 65535:
        end = 65535
    if start > end:
        start, end = end, start
    return list(range(start, end + 1))


def run_scan(target: str, ports: List[int], do_tcp: bool, do_udp: bool, timeout: float, workers: int = 200):
    results = {
        'tcp': [],  # tuples (porta, status)
        'udp': []
    }

    # Resolving target IP (se for um hostname)
    try:
        target_ip = socket.gethostbyname(target)
    except Exception as e:
        raise RuntimeError(f"Não foi possível resolver o host '{target}': {e}")

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = []

        if do_tcp:
            for p in ports:
                futures.append(executor.submit(scan_tcp_port, target_ip, p, timeout))

        if do_udp:
            for p in ports:
                futures.append(executor.submit(scan_udp_port, target_ip, p, timeout))

        for fut in concurrent.futures.as_completed(futures):
            try:
                port, status = fut.result()
            except Exception:
                continue

            # Determinar se foi TCP ou UDP pela presença do resultado em portas e do tipo de função

            # Se status == 'closed' -> assume TCP; if 'open|filtered' -> UDP; if 'open' -> tentar verificação dupla
            if status == 'closed':
                results['tcp'].append((port, status))
            elif status == 'open|filtered':
                results['udp'].append((port, status))
            elif status == 'open':
                # Pode ser TCP ou UDP; para colocar de forma útil, verifica a porta com TCP rapidamente
                # Essa verificação extra é útil para classificar corretamente portas TCP abertas
                try:
                    # checa conexão TCP rápida com timeout baixo
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        if s.connect_ex((target_ip, port)) == 0:
                            results['tcp'].append((port, 'open'))
                        else:
                            # sem conexão -> assume UDP que respondeu
                            results['udp'].append((port, 'open'))
                except Exception:
                    results['udp'].append((port, 'open'))
            else:
                # status == 'error' ou outro -> guardar em ambos para inspeção manual
                results['tcp'].append((port, status))

    elapsed = time.time() - start_time
    return target_ip, results, elapsed


def save_results(output_file: str, target: str, target_ip: str, ports: List[int], results: dict, elapsed: float, args):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Scanner simples - resultado\n")
        f.write(f"Alvo: {target} ({target_ip})\n")
        f.write(f"Portas verificadas: {ports[0]}-{ports[-1]} ({len(ports)} portas)\n")
        f.write(f"Protocolos: {'TCP' if args.tcp else ''}{' UDP' if args.udp else ''}\n")
        f.write(f"Timeout por porta: {args.timeout}s\n")
        f.write(f"Início: {datetime.now().isoformat()}\n")
        f.write(f"Tempo total: {elapsed:.2f}s\n\n")

        f.write('--- TCP ---\n')
        if results['tcp']:
            for port, status in sorted(results['tcp'], key=lambda x: x[0]):
                f.write(f"{port}\t{status}\n")
        else:
            f.write('Nenhum resultado TCP\n')

        f.write('\n--- UDP ---\n')
        if results['udp']:
            for port, status in sorted(results['udp'], key=lambda x: x[0]):
                f.write(f"{port}\t{status}\n")
        else:
            f.write('Nenhum resultado UDP\n')

    return output_file


def main():
    parser = argparse.ArgumentParser(description='Scanner de portas TCP/UDP simples')
    parser.add_argument('--target', required=True, help='IP ou hostname do alvo')
    parser.add_argument('--start', type=int, default=1, help='Porta inicial (padrão 1)')
    parser.add_argument('--end', type=int, default=1024, help='Porta final (padrão 1024)')
    parser.add_argument('--tcp', action='store_true', help='Fazer varredura TCP')
    parser.add_argument('--udp', action='store_true', help='Fazer varredura UDP')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout por porta em segundos (padrão 1.0)')
    parser.add_argument('--workers', type=int, default=200, help='Número de threads concorrentes (padrão 200)')
    parser.add_argument('--output', default='scan_result.txt', help='Arquivo de saída para resultados (padrão scan_result.txt)')

    args = parser.parse_args()

    if not args.tcp and not args.udp:
        args.tcp = True
        args.udp = True

    ports = parse_port_range(args.start, args.end)

    print(f"Iniciando varredura em {args.target} para portas {ports[0]}-{ports[-1]} (TCP={args.tcp}, UDP={args.udp})")

    try:
        target_ip, results, elapsed = run_scan(args.target, ports, args.tcp, args.udp, args.timeout, args.workers)
    except RuntimeError as e:
        print(f"Erro: {e}")
        return

    out_file = save_results(args.output, args.target, target_ip, ports, results, elapsed, args)

    print('\nVarredura finalizada!')
    print(f"Alvo: {args.target} ({target_ip})")
    print(f"Tempo total: {elapsed:.2f}s")
    print(f"Resultados salvos em: {out_file}")

    if results['tcp']:
        open_tcp = [p for p, s in results['tcp'] if s == 'open']
        if open_tcp:
            print('\nTCP - portas abertas:')
            print(', '.join(map(str, open_tcp)))
    if results['udp']:
        udp_open = [p for p, s in results['udp'] if s in ('open', 'open|filtered')]
        if udp_open:
            print('\nUDP - portas com resposta / open|filtered:')
            print(', '.join(map(str, udp_open)))


if __name__ == '__main__':
    main()
