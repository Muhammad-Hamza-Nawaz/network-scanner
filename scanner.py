import socket
import threading
from typing import List, Dict

try:
    import nmap
    HAS_NMAP = True
except Exception:
    HAS_NMAP = False


def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    parts = ports_str.split(',')
    for p in parts:
        p = p.strip()
        if '-' in p:
            a,b = p.split('-',1)
            ports.update(range(int(a), int(b)+1))
        else:
            if p:
                ports.add(int(p))
    return sorted(ports)


def _tcp_connect_scan(target: str, ports: List[int], timeout: float = 1.0) -> List[Dict]:
    results = []
    lock = threading.Lock()

    def worker(port:int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((target, port))
            status = 'open' if code == 0 else 'closed'
        except Exception:
            status = 'filtered'
        finally:
            try:
                s.close()
            except Exception:
                pass
        with lock:
            results.append({"ip": target, "port": port, "service": "unknown", "status": status})

    threads = []
    for port in ports:
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return sorted(results, key=lambda x: x['port'])


def run_scan(target: str, scan_type: str, ports: str) -> List[Dict]:
    """Run a scan and return list of results: {ip, port, service, status}.
    scan_type: 'tcp' or 'udp' (udp is best-effort)
    ports: string like '22,80,8000-8100'
    """
    port_list = parse_ports(ports)
    if HAS_NMAP:
        nm = nmap.PortScanner()
        args = ''
        if scan_type == 'tcp':
            args = '-sS'
        elif scan_type == 'udp':
            args = '-sU'
        else:
            args = ''
        pm = nm.scan(hosts=target, ports=','.join(map(str, port_list)), arguments=args)
        out = []
        scanned = pm.get('scan', {})
        hostinfo = scanned.get(target, {})
        tcp = hostinfo.get('tcp', {})
        udp = hostinfo.get('udp', {})
        proto = tcp if scan_type == 'tcp' else udp
        for p,info in proto.items():
            out.append({"ip": target, "port": int(p), "service": info.get('name',''), "status": info.get('state','')})
        return sorted(out, key=lambda x: x['port'])
    else:
        # Fallback: simple TCP connect scan
        if scan_type == 'tcp':
            return _tcp_connect_scan(target, port_list)
        elif scan_type == 'udp':
            # UDP fallback: send an empty UDP packet and wait briefly for any response.
            return _udp_probe_scan(target, port_list)
        else:
            # default to tcp
            return _tcp_connect_scan(target, port_list)


def _udp_probe_scan(target: str, ports: List[int], timeout: float = 1.0) -> List[Dict]:
    """Best-effort UDP probe: send an empty datagram to each port and wait for a short response.
    Note: reliable UDP scanning requires raw sockets or nmap; this is a lightweight fallback.
    """
    import select
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setblocking(0)
        try:
            try:
                s.sendto(b'', (target, port))
            except Exception:
                pass
            # wait for readable socket (UDP response) within timeout
            rlist, _, _ = select.select([s], [], [], timeout)
            if rlist:
                try:
                    data, addr = s.recvfrom(4096)
                    status = 'open'
                except Exception:
                    status = 'open'
            else:
                # no response: could be open|filtered
                status = 'open|filtered'
        finally:
            try:
                s.close()
            except Exception:
                pass
        results.append({"ip": target, "port": port, "service": "unknown", "status": status})
    return results
