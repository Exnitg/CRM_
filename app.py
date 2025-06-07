from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import subprocess
import threading
import time
import os
import signal
import json
from datetime import datetime
import queue
import re
import socket
import requests
from functools import lru_cache

app = Flask(__name__)
app.config['SECRET_KEY'] = 'xxxxxx'
socketio = SocketIO(app, cors_allowed_origins="*")

class TCPDumpMonitor:
    def __init__(self):
        self.process = None
        self.is_running = False
        self.router_ip = "192.168.1.10"
        self.interface = "br0"
        self.packet_details = {}  # Хранение полных деталей пакетов
        
    def start_capture(self, filter_expr="", verbose_level=1, exclude_ssh=True, exclude_ports=None):
        """Запуск захвата трафика с исключениями"""
        try:
            # Формируем фильтр с исключениями
            final_filter = self.build_filter(filter_expr, exclude_ssh, exclude_ports)
        
            verbose_flags = {
                1: "-v",
                2: "-vv", 
                3: "-vvv"
            }
            
            verbose_flag = verbose_flags.get(verbose_level, "-vv")
            
            cmd = [
                'ssh', f'router@{self.router_ip}',
                f'/media/FLASH/tcpdump-mt7620 -i {self.interface} -l -n {verbose_flag}'
            ]
            
            if final_filter:
                cmd[-1] += f' {final_filter}'
        
            print(f"Запуск команды: {' '.join(cmd)}")
            print(f"Итоговый фильтр: {final_filter}")
        
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )
        
            self.is_running = True
            return True, final_filter
        
        except Exception as e:
            print(f"Ошибка запуска tcpdump: {e}")
            return False, ""
    
    def build_filter(self, user_filter, exclude_ssh, exclude_ports):
        """Построение фильтра с исключениями"""
        exclusions = []
        
        # Исключаем SSH (порт 22)
        if exclude_ssh:
            exclusions.append("not port 22")
        
        # Исключаем дополнительные порты
        if exclude_ports:
            for port in exclude_ports:
                if port.strip() and port.strip().isdigit():
                    exclusions.append(f"not port {port.strip()}")
        
        # Объединяем исключения
        exclusion_filter = " and ".join(exclusions)
        
        # Комбинируем с пользовательским фильтром
        if user_filter and exclusion_filter:
            return f"({user_filter}) and ({exclusion_filter})"
        elif user_filter:
            return f"{user_filter} and ({exclusion_filter})" if exclusion_filter else user_filter
        elif exclusion_filter:
            return exclusion_filter
        else:
            return ""
    
    def stop_capture(self):
        """Остановка захвата"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            finally:
                self.process = None
                self.is_running = False
    
    def read_output(self):
        """Чтение вывода tcpdump"""
        if self.process and self.process.stdout:
            try:
                line = self.process.stdout.readline()
                if line:
                    return line.strip()
                elif self.process.poll() is not None:
                    self.is_running = False
                    return None
            except Exception as e:
                print(f"Ошибка чтения вывода: {e}")
                self.is_running = False
        return None

monitor = TCPDumpMonitor()

# Кэш для IP информации
@lru_cache(maxsize=1000)
def get_ip_info(ip_address):
    """Получение информации об IP адресе"""
    try:
        # Проверяем, что это внешний IP
        if is_local_ip(ip_address):
            return {
                'provider': 'Local Network',
                'country': 'Local',
                'city': 'Local',
                'service': 'Local Network',
                'is_local': True
            }
        
        # Получаем имя сервиса
        service_name = get_service_name_by_ip(ip_address)
        
        # Используем API для получения информации об IP
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    'provider': data.get('isp', 'Unknown'),
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', ''),
                    'service': service_name or data.get('org', ''),
                    'is_local': False
                }
    except Exception as e:
        print(f"Ошибка получения информации об IP {ip_address}: {e}")
    
    # Если API не сработал, но сервис определился
    service_name = get_service_name_by_ip(ip_address)
    return {
        'provider': 'Unknown',
        'country': 'Unknown', 
        'city': 'Unknown',
        'service': service_name,
        'is_local': False
    }

def is_local_ip(ip):
    """Проверка, является ли IP локальным"""
    local_networks = [
        '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.', '169.254.'
    ]
    return any(ip.startswith(net) for net in local_networks)

# База известных сервисов
KNOWN_SERVICES = {
    # Google
    '8.8.8.8': 'Google DNS',
    '8.8.4.4': 'Google DNS',
    '172.217.': 'Google Services',
    '216.58.': 'Google Services',
    '74.125.': 'Google Services',
    
    # Cloudflare
    '1.1.1.1': 'Cloudflare DNS',
    '1.0.0.1': 'Cloudflare DNS',
    '104.16.': 'Cloudflare CDN',
    '104.17.': 'Cloudflare CDN',
    
    # Facebook/Meta
    '31.13.': 'Facebook/Meta',
    '157.240.': 'Facebook/Meta',
    '173.252.': 'Facebook/Meta',
    
    # Amazon AWS
    '52.': 'Amazon AWS',
    '54.': 'Amazon AWS',
    '3.': 'Amazon AWS',
    
    # Microsoft
    '13.': 'Microsoft Azure',
    '20.': 'Microsoft Services',
    '40.': 'Microsoft Azure',
    '52.': 'Microsoft Azure',
    
    # Telegram
    '149.154.': 'Telegram',
    '91.108.': 'Telegram',
    
    # WhatsApp
    '31.13.': 'WhatsApp/Facebook',
    '157.240.': 'WhatsApp/Facebook',
    
    # YouTube/Google
    '172.217.': 'YouTube/Google',
    '216.58.': 'YouTube/Google',
    
    # VK
    '87.240.': 'VKontakte',
    '95.213.': 'VKontakte',
    
    # Yandex
    '77.88.': 'Yandex',
    '213.180.': 'Yandex',
    '87.250.': 'Yandex',
    
    # Mail.ru
    '94.100.': 'Mail.ru',
    '217.69.': 'Mail.ru',
    
    # Discord
    '162.159.': 'Discord',
    '104.16.': 'Discord/Cloudflare',
}

@lru_cache(maxsize=500)
def get_service_name_by_ip(ip_address):
    """Определение имени сервиса по IP адресу"""
    try:
        # Проверяем известные сервисы
        for ip_prefix, service_name in KNOWN_SERVICES.items():
            if ip_address.startswith(ip_prefix):
                return service_name
        
        # Пытаемся сделать reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            
            # Анализируем hostname для определения сервиса
            hostname_lower = hostname.lower()
            
            if 'google' in hostname_lower or 'gmail' in hostname_lower:
                return 'Google Services'
            elif 'facebook' in hostname_lower or 'fb' in hostname_lower:
                return 'Facebook/Meta'
            elif 'whatsapp' in hostname_lower:
                return 'WhatsApp'
            elif 'telegram' in hostname_lower:
                return 'Telegram'
            elif 'youtube' in hostname_lower:
                return 'YouTube'
            elif 'microsoft' in hostname_lower or 'outlook' in hostname_lower:
                return 'Microsoft'
            elif 'amazon' in hostname_lower or 'aws' in hostname_lower:
                return 'Amazon AWS'
            elif 'cloudflare' in hostname_lower:
                return 'Cloudflare'
            elif 'yandex' in hostname_lower:
                return 'Yandex'
            elif 'vk.com' in hostname_lower or 'vkontakte' in hostname_lower:
                return 'VKontakte'
            elif 'mail.ru' in hostname_lower:
                return 'Mail.ru'
            elif 'discord' in hostname_lower:
                return 'Discord'
            else:
                # Возвращаем домен верхнего уровня
                parts = hostname_lower.split('.')
                if len(parts) >= 2:
                    return f"{parts[-2]}.{parts[-1]}"
                return hostname
                
        except socket.herror:
            # Если reverse DNS не удался, возвращаем пустую строку
            return ''
            
    except Exception as e:
        print(f"Ошибка определения сервиса для IP {ip_address}: {e}")
        return ''
    
    return ''

def capture_worker():
    global monitor
    packet_id = 0
    buffer = []

    while monitor.is_running:
        line = monitor.read_output()
        if line is None:
            time.sleep(0.01)
            continue

        # Начало нового пакета — если уже есть данные в буфере
        if re.match(r'^\d{2}:\d{2}:\d{2}\.\d{6} ', line) and buffer:
            full_packet = ' '.join(buffer)
            packet_id += 1
            handle_packet(full_packet, packet_id)
            buffer = []

        buffer.append(line.strip())

    # Обработка последнего пакета при остановке
    if buffer:
        full_packet = ' '.join(buffer)
        packet_id += 1
        handle_packet(full_packet, packet_id)

def handle_packet(packet_text, packet_id):
    parsed_data = parse_tcpdump_line_detailed(packet_text)
    monitor.packet_details[packet_id] = {
        'raw': packet_text,
        'parsed': parsed_data,
        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3]
    }

    ip_info = {}
    if parsed_data.get('src_ip'):
        ip_info['src_info'] = get_ip_info(parsed_data['src_ip'])
    if parsed_data.get('dst_ip'):
        ip_info['dst_info'] = get_ip_info(parsed_data['dst_ip'])

    socketio.emit('new_packet', {
        'id': packet_id,
        'raw': packet_text,
        'parsed': parsed_data,
        'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
        'ip_info': ip_info
    })

def parse_tcpdump_line_detailed(line):
    """Детальный парсинг строки tcpdump"""
    try:
        # Пропускаем hex dump строки
        if re.match(r'^\s*0x[0-9a-f]+:', line):
            return {
                'type': 'hex_dump',
                'data': line.strip()
            }
        
        # Пропускаем ASCII dump строки
        if re.match(r'^\s+[^\s]', line) and not ':' in line[:20]:
            return {
                'type': 'ascii_dump', 
                'data': line.strip()
            }
        
        parts = line.split()
        if len(parts) < 3:
            return {'type': 'unknown', 'data': line}
        
        timestamp = parts[0]
        
        # IP пакеты
        if 'IP' in line:
            return parse_ip_packet(line, timestamp)
        
        # ARP пакеты
        elif 'ARP' in line:
            return parse_arp_packet(line, timestamp)
        
        # ICMP пакеты
        elif 'ICMP' in line:
            return parse_icmp_packet(line, timestamp)
        
        # Другие протоколы
        else:
            return {
                'type': 'other',
                'timestamp': timestamp,
                'data': line,
                'protocol': 'UNKNOWN'
            }
        
    except Exception as e:
        return {
            'type': 'error',
            'data': line,
            'error': str(e)
        }

def parse_ip_packet(line, timestamp):
    """Парсинг IP пакета"""
    try:
        # Извлекаем основную информацию
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\.?(\d+)?\s*>\s*(\d+\.\d+\.\d+\.\d+)\.?(\d+)?', line)
        
        if not ip_match:
            return {'type': 'ip', 'timestamp': timestamp, 'data': line}
        
        src_ip = ip_match.group(1)
        src_port = ip_match.group(2) or ''
        dst_ip = ip_match.group(3)
        dst_port = ip_match.group(4) or ''
        
        # Определяем протокол
        protocol = 'IP'
        if 'tcp' in line.lower():
            protocol = 'TCP'
        elif 'udp' in line.lower():
            protocol = 'UDP'
        
        # Извлекаем дополнительную информацию
        packet_info = {
            'type': 'ip',
            'timestamp': timestamp,
            'protocol': protocol,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'src_hostname': resolve_hostname(src_ip),
            'dst_hostname': resolve_hostname(dst_ip),
            'service': get_service_name(dst_port) if dst_port else '',
            'size': extract_packet_size(line),
            'flags': extract_tcp_flags(line) if protocol == 'TCP' else '',
            'seq': extract_sequence_numbers(line) if protocol == 'TCP' else '',
            'ttl': extract_ttl(line),
            'window': extract_window_size(line) if protocol == 'TCP' else '',
            'direction': determine_direction(src_ip, dst_ip),
            'data_summary': extract_data_summary(line)
        }
        
        return packet_info
        
    except Exception as e:
        return {
            'type': 'ip',
            'timestamp': timestamp,
            'data': line,
            'error': str(e)
        }

def parse_arp_packet(line, timestamp):
    """Парсинг ARP пакета"""
    try:
        # ARP who-has или reply
        if 'who-has' in line:
            match = re.search(r'who-has (\d+\.\d+\.\d+\.\d+) tell (\d+\.\d+\.\d+\.\d+)', line)
            if match:
                return {
                    'type': 'arp',
                    'timestamp': timestamp,
                    'protocol': 'ARP',
                    'arp_type': 'REQUEST',
                    'target_ip': match.group(1),
                    'sender_ip': match.group(2),
                    'target_hostname': resolve_hostname(match.group(1)),
                    'sender_hostname': resolve_hostname(match.group(2)),
                    'data': line
                }
        elif 'reply' in line:
            match = re.search(r'(\d+\.\d+\.\d+\.\d+) is-at ([a-f0-9:]+)', line)
            if match:
                return {
                    'type': 'arp',
                    'timestamp': timestamp,
                    'protocol': 'ARP',
                    'arp_type': 'REPLY',
                    'sender_ip': match.group(1),
                    'sender_mac': match.group(2),
                    'sender_hostname': resolve_hostname(match.group(1)),
                    'data': line
                }
        
        return {
            'type': 'arp',
            'timestamp': timestamp,
            'protocol': 'ARP',
            'data': line
        }
        
    except Exception as e:
        return {
            'type': 'arp',
            'timestamp': timestamp,
            'data': line,
            'error': str(e)
        }

def parse_icmp_packet(line, timestamp):
    """Парсинг ICMP пакета"""
    try:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)', line)
        
        packet_info = {
            'type': 'icmp',
            'timestamp': timestamp,
            'protocol': 'ICMP',
            'data': line
        }
        
        if ip_match:
            packet_info.update({
                'src_ip': ip_match.group(1),
                'dst_ip': ip_match.group(2),
                'src_hostname': resolve_hostname(ip_match.group(1)),
                'dst_hostname': resolve_hostname(ip_match.group(2)),
                'direction': determine_direction(ip_match.group(1), ip_match.group(2))
            })
        
        # Определяем тип ICMP
        if 'echo request' in line:
            packet_info['icmp_type'] = 'PING REQUEST'
        elif 'echo reply' in line:
            packet_info['icmp_type'] = 'PING REPLY'
        elif 'unreachable' in line:
            packet_info['icmp_type'] = 'UNREACHABLE'
        else:
            packet_info['icmp_type'] = 'OTHER'
        
        return packet_info
        
    except Exception as e:
        return {
            'type': 'icmp',
            'timestamp': timestamp,
            'data': line,
            'error': str(e)
        }

def resolve_hostname(ip):
    """Разрешение имени хоста по IP"""
    try:
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return f"local-{ip.split('.')[-1]}"
        
        if ip.startswith('8.8.8.'):
            return "Google-DNS"
        elif ip.startswith('1.1.1.'):
            return "Cloudflare-DNS"
        else:
            return ""
            
    except:
        return ""

def get_service_name(port):
    """Получение имени сервиса по порту"""
    services = {
        '20': 'FTP-DATA', '21': 'FTP', '22': 'SSH', '23': 'TELNET',
        '25': 'SMTP', '53': 'DNS', '67': 'DHCP-S', '68': 'DHCP-C',
        '80': 'HTTP', '110': 'POP3', '143': 'IMAP', '443': 'HTTPS',
        '993': 'IMAPS', '995': 'POP3S', '587': 'SMTP-TLS',
        '8080': 'HTTP-ALT', '3389': 'RDP', '5060': 'SIP'
    }
    return services.get(port, '')

def extract_packet_size(line):
    """Извлечение размера пакета"""
    size_match = re.search(r'length (\d+)', line)
    return size_match.group(1) if size_match else ''

def extract_tcp_flags(line):
    """Извлечение TCP флагов"""
    flags_match = re.search(r'Flags \[([^\]]+)\]', line)
    if flags_match:
        flags = flags_match.group(1)
        flag_meanings = {
            'S': 'SYN', 'F': 'FIN', 'R': 'RST', 'P': 'PSH',
            'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
        }
        
        decoded_flags = []
        for flag in flags.replace('.', ''):
            if flag in flag_meanings:
                decoded_flags.append(flag_meanings[flag])
        
        return f"{flags} ({', '.join(decoded_flags)})" if decoded_flags else flags
    return ''

def extract_sequence_numbers(line):
    """Извлечение sequence numbers"""
    seq_match = re.search(r'seq (\d+):?(\d+)?', line)
    ack_match = re.search(r'ack (\d+)', line)
    
    result = []
    if seq_match:
        if seq_match.group(2):
            result.append(f"seq {seq_match.group(1)}:{seq_match.group(2)}")
        else:
            result.append(f"seq {seq_match.group(1)}")
    
    if ack_match:
        result.append(f"ack {ack_match.group(1)}")
    
    return ', '.join(result)

def extract_ttl(line):
    """Извлечение TTL"""
    ttl_match = re.search(r'ttl (\d+)', line)
    return ttl_match.group(1) if ttl_match else ''

def extract_window_size(line):
    """Извлечение размера окна"""
    win_match = re.search(r'win (\d+)', line)
    return win_match.group(1) if win_match else ''

def determine_direction(src_ip, dst_ip):
    """Определение направления трафика"""
    local_networks = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
    
    src_local = any(src_ip.startswith(net) for net in local_networks)
    dst_local = any(dst_ip.startswith(net) for net in local_networks)
    
    if src_local and dst_local:
        return 'LOCAL'
    elif src_local and not dst_local:
        return 'OUTBOUND'
    elif not src_local and dst_local:
        return 'INBOUND'
    else:
        return 'EXTERNAL'

def extract_data_summary(line):
    """Извлечение краткого описания данных"""
    if 'HTTP' in line:
        return 'HTTP Traffic'
    elif 'TLS' in line or 'SSL' in line:
        return 'Encrypted (TLS/SSL)'
    elif 'DNS' in line:
        return 'DNS Query/Response'
    elif 'DHCP' in line:
        return 'DHCP Traffic'
    else:
        return ''

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    global monitor, capture_thread
    
    data = request.json
    filter_expr = data.get('filter', '')
    verbose_level = data.get('verbose_level', 2)
    exclude_ssh = data.get('exclude_ssh', True)
    exclude_ports = data.get('exclude_ports', [])
    
    if monitor.is_running:
        return jsonify({'success': False, 'message': 'Захват уже запущен'})
    
    success, final_filter = monitor.start_capture(filter_expr, verbose_level, exclude_ssh, exclude_ports)
    
    if success:
        capture_thread = threading.Thread(target=capture_worker)
        capture_thread.daemon = True
        capture_thread.start()
        
        return jsonify({
            'success': True, 
            'message': 'Захват запущен',
            'filter': final_filter
        })
    else:
        return jsonify({'success': False, 'message': 'Ошибка запуска захвата'})

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    global monitor
    monitor.stop_capture()
    return jsonify({'success': True, 'message': 'Захват остановлен'})

@app.route('/api/status')
def get_status():
    return jsonify({
        'is_running': monitor.is_running,
        'router_ip': monitor.router_ip,
        'interface': monitor.interface
    })

@app.route('/api/packet/<int:packet_id>')
def get_packet_details(packet_id):
    """Получение полных деталей пакета"""
    if packet_id in monitor.packet_details:
        return jsonify(monitor.packet_details[packet_id])
    else:
        return jsonify({'error': 'Пакет не найден'}), 404

@socketio.on('connect')
def handle_connect():
    print('Клиент подключился')
    emit('status', {'is_running': monitor.is_running})

@socketio.on('disconnect')
def handle_disconnect():
    print('Клиент отключился')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
