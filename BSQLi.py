#!/usr/bin/env python3
"""
BSQLi - Blind SQL Injection Scanner
"""

import requests
import time
import argparse
import sys
import re
import json
import base64
import html
from urllib.parse import urlparse, parse_qs, urlunparse
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class Logger:
    @staticmethod
    def info(msg):
        print(f"{Colors.CYAN}[INFO]{Colors.END} {msg}")

    @staticmethod
    def success(msg):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.END} {msg}")

    @staticmethod
    def warning(msg):
        print(f"{Colors.YELLOW}[WARNING]{Colors.END} {msg}")

    @staticmethod
    def error(msg):
        print(f"{Colors.RED}[ERROR]{Colors.END} {msg}")

    @staticmethod
    def critical(msg):
        print(f"{Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.END} {msg}")

    @staticmethod
    def debug(msg):
        print(f"{Colors.MAGENTA}[DEBUG]{Colors.END} {msg}")

class AdvancedParameterDetector:
    """Advanced parameter detection from Burp Suite requests"""
    
    @staticmethod
    def parse_burp_request(filename):
        """Parse Burp Suite request file with enhanced detection"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.strip().split('\n')
            
            if not lines:
                raise ValueError("Empty request file")
            
            # Parse request line
            first_line = lines[0].strip()
            parts = first_line.split()
            if len(parts) < 3:
                raise ValueError("Invalid request line")
            
            method, path, http_version = parts[0], parts[1], parts[2]
            
            # Extract headers and body
            headers = {}
            body = ""
            body_started = False
            
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    body_started = True
                    continue
                
                if not body_started:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
                else:
                    body += line + '\n'
            
            body = body.strip()
            
            # Build URL
            host = headers.get('Host', '')
            if not host:
                raise ValueError("No Host header found")
            
            scheme = 'https' if ':443' in host or headers.get('X-Forwarded-Proto') == 'https' else 'http'
            url = f"{scheme}://{host}{path}"
            
            return {
                'method': method.upper(),
                'url': url,
                'headers': headers,
                'body': body,
                'raw_request': content
            }
            
        except Exception as e:
            Logger.error(f"Error parsing Burp request: {e}")
            sys.exit(1)

    @staticmethod
    def detect_parameters_from_url(url):
        """Detect parameters from a simple URL"""
        parameters = []
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            parameters.extend(query_params.keys())
        
        return parameters

    @staticmethod
    def detect_all_parameters(request_info):
        """Detect ALL possible parameters from request"""
        parameters = []
        
        # 1. URL Query Parameters
        parsed_url = urlparse(request_info['url'])
        if parsed_url.query:
            query_params = parse_qs(parsed_url.query)
            parameters.extend(query_params.keys())
        
        # 2. POST Body Parameters
        body = request_info['body']
        content_type = request_info['headers'].get('Content-Type', '').lower()
        
        if body:
            # Form Data (application/x-www-form-urlencoded)
            if 'application/x-www-form-urlencoded' in content_type or ('=' in body and '&' in body):
                try:
                    body_params = parse_qs(body)
                    form_params = list(body_params.keys())
                    parameters.extend(form_params)
                except:
                    pass
            
            # JSON Parameters
            elif 'application/json' in content_type or (body.strip().startswith('{') and body.strip().endswith('}')):
                try:
                    json_data = json.loads(body)
                    json_params = AdvancedParameterDetector.extract_json_paths(json_data)
                    parameters.extend(json_params)
                except Exception as e:
                    pass
            
            # Generic key=value detection (fallback)
            else:
                generic_params = AdvancedParameterDetector.extract_generic_parameters(body)
                parameters.extend(generic_params)
        
        # 3. Cookie Parameters
        cookie_params = AdvancedParameterDetector.extract_cookie_parameters(request_info['headers'])
        parameters.extend(cookie_params)
        
        # Remove duplicates and return
        unique_params = list(set(parameters))
        return unique_params

    @staticmethod
    def extract_json_paths(data, current_path=""):
        """Extract all JSON paths recursively"""
        paths = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{current_path}.{key}" if current_path else key
                paths.append(new_path)
                if isinstance(value, (dict, list)):
                    paths.extend(AdvancedParameterDetector.extract_json_paths(value, new_path))
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{current_path}[{i}]"
                paths.append(new_path)
                if isinstance(item, (dict, list)):
                    paths.extend(AdvancedParameterDetector.extract_json_paths(item, new_path))
        
        return paths

    @staticmethod
    def extract_generic_parameters(body):
        """Extract parameters using generic patterns"""
        params = []
        
        # key=value pattern
        key_value_pairs = re.findall(r'([a-zA-Z_][a-zA-Z0-9_]*)=[^&]*', body)
        params.extend(key_value_pairs)
        
        # JSON-like patterns without full JSON structure
        json_like = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)":', body)
        params.extend(json_like)
        
        return list(set(params))

    @staticmethod
    def extract_cookie_parameters(headers):
        """Extract cookie parameters"""
        cookies = headers.get('Cookie', '')
        if cookies:
            cookie_params = []
            cookie_pairs = cookies.split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    key = pair.split('=')[0].strip()
                    cookie_params.append(f"cookie:{key}")
            return cookie_params
        return []

class EnhancedBSQLIAnalyzer:
    def __init__(self, timeout=30, delay=1, encoding=None, verbose=False):
        self.timeout = timeout
        self.delay = delay
        self.encoding = encoding
        self.verbose = verbose
        self.session = requests.Session()
        self.found_vulnerabilities = []
        
        # NO añadir headers por defecto - usar solo los del archivo Burp
        self.session.headers.clear()

    def load_wordlist(self, filename):
        """Load time-based payloads"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            time_payloads = []
            for payload in payloads:
                if any(keyword in payload.upper() for keyword in ['SLEEP', 'WAITFOR', 'DELAY', 'PG_SLEEP', 'BENCHMARK']):
                    time_payloads.append(payload)
            
            Logger.info(f"Loaded {len(time_payloads)} time-based payloads")
            return time_payloads
            
        except FileNotFoundError:
            Logger.error(f"Wordlist file not found: {filename}")
            sys.exit(1)
        except Exception as e:
            Logger.error(f"Error reading wordlist: {e}")
            sys.exit(1)

    def load_url_list(self, filename):
        """Load list of URLs from file"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            Logger.info(f"Loaded {len(urls)} URLs from list")
            return urls
            
        except FileNotFoundError:
            Logger.error(f"URL list file not found: {filename}")
            sys.exit(1)
        except Exception as e:
            Logger.error(f"Error reading URL list: {e}")
            sys.exit(1)

    def build_url_without_encoding(self, original_url, parameter, payload):
        """Build URL without any encoding - replace parameter value directly"""
        parsed_url = urlparse(original_url)
        
        if not parsed_url.query:
            return f"{original_url}?{parameter}={payload}"
            
        # Parse query string manually to avoid encoding
        query_parts = []
        for part in parsed_url.query.split('&'):
            if '=' in part:
                key, value = part.split('=', 1)
                if key == parameter:
                    # Reemplazar solo este parámetro con el payload SIN encoding
                    query_parts.append(f"{key}={payload}")
                else:
                    # Mantener otros parámetros exactamente igual
                    query_parts.append(f"{key}={value}")
            else:
                query_parts.append(part)
        
        new_query = '&'.join(query_parts)
        
        # Reconstruir URL sin encoding
        modified_url = urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        return modified_url

    def modify_body_without_encoding(self, original_body, parameter, payload):
        """Modify body without any encoding - replace parameter value directly"""
        if not original_body:
            return f"{parameter}={payload}"
            
        # Buscar y reemplazar el parámetro específico sin encoding
        body_parts = []
        for part in original_body.split('&'):
            if '=' in part:
                key, value = part.split('=', 1)
                if key == parameter:
                    body_parts.append(f"{key}={payload}")
                else:
                    body_parts.append(f"{key}={value}")
            else:
                body_parts.append(part)
        
        return '&'.join(body_parts)

    def send_modified_request(self, request_info, parameter, payload):
        """Send request with modified parameter - EXACTLY as in Burp file, NO encoding"""
        try:
            method = request_info['method']
            original_url = request_info['url']
            
            # Usar EXACTAMENTE los headers del archivo Burp - sin modificaciones
            headers = request_info['headers'].copy()
            original_body = request_info['body']
            
            # NO aplicar encoding - usar payload tal cual
            final_payload = payload
            
            if self.verbose:
                Logger.debug(f"Using payload without encoding: {final_payload}")

            # Determine parameter type and modify accordingly
            if parameter.startswith('cookie:'):
                # Cookie parameter - modificar SOLO la cookie específica
                cookie_name = parameter.replace('cookie:', '')
                cookies = headers.get('Cookie', '')
                if cookies:
                    cookie_pairs = []
                    for pair in cookies.split(';'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            if key.strip() == cookie_name:
                                # Reemplazar solo el valor de esta cookie
                                cookie_pairs.append(f"{key.strip()}={final_payload}")
                            else:
                                # Mantener las otras cookies exactamente igual
                                cookie_pairs.append(f"{key.strip()}={value.strip()}")
                    
                    headers['Cookie'] = '; '.join(cookie_pairs)
                
                modified_body = original_body
                modified_url = original_url
                
            else:
                # URL or Body parameter
                parsed_url = urlparse(original_url)
                
                if parameter in parse_qs(parsed_url.query):
                    # URL parameter - reemplazar sin encoding
                    modified_url = self.build_url_without_encoding(original_url, parameter, final_payload)
                    modified_body = original_body
                else:
                    # Body parameter - reemplazar sin encoding
                    modified_url = original_url
                    modified_body = self.modify_body_without_encoding(original_body, parameter, final_payload)
            
            # Debug information in verbose mode
            if self.verbose:
                Logger.debug(f"Request Method: {method}")
                Logger.debug(f"Request URL: {modified_url}")
                Logger.debug(f"Request Headers: {dict(headers)}")
                Logger.debug(f"Request Body: {modified_body}")
                Logger.debug(f"Parameter: {parameter}")
                Logger.debug(f"Original Payload: {payload}")
                Logger.debug(f"Final Payload Being Sent: {final_payload}")
                Logger.debug(f"Encoding: NONE - payload sent as-is")
            
            # Send request EXACTLY as in Burp file, only changing the parameter value
            # PERMITIR redirects para que funcione correctamente
            response = self.session.request(
                method,
                modified_url,
                headers=headers,  # Headers exactos del archivo Burp
                data=modified_body,
                timeout=self.timeout,
                allow_redirects=True,  # PERMITIR redirects para casos como 301
                verify=False
            )
            
            if self.verbose:
                Logger.debug(f"Response Status: {response.status_code}")
                Logger.debug(f"Response Time: {response.elapsed.total_seconds():.2f}s")
                Logger.debug(f"Response Size: {len(response.content)} bytes")
                if response.history:
                    Logger.debug(f"Redirect history: {[r.status_code for r in response.history]}")
            
            return response
            
        except requests.exceptions.Timeout:
            if self.verbose:
                Logger.debug("Request TIMEOUT")
            return "TIMEOUT"
        except Exception as e:
            if self.verbose:
                Logger.debug(f"Request Exception: {e}")
            return None

    def get_base_response_time(self, request_info, parameter):
        """Get baseline response time usando el valor ORIGINAL del request"""
        if self.verbose:
            Logger.debug(f"Getting baseline for parameter: {parameter}")
        
        try:
            times = []
            for i in range(3):  # Más intentos para baseline más preciso
                start_time = time.perf_counter()
                # Para baseline, enviar la petición ORIGINAL sin modificar
                response = self.send_original_request(request_info)
                end_time = time.perf_counter()
                
                # Considerar cualquier status code como válido para baseline
                if response:
                    times.append(end_time - start_time)
                    if self.verbose:
                        Logger.debug(f"Baseline attempt {i+1}: {end_time - start_time:.2f}s - Status: {response.status_code}")
                time.sleep(0.5)  # Pequeña pausa entre requests
            
            if times:
                base_time = sum(times) / len(times)
                if self.verbose:
                    Logger.debug(f"Average baseline: {base_time:.2f}s")
                return base_time
            
            return 1.0  # Baseline más conservador
            
        except Exception as e:
            if self.verbose:
                Logger.debug(f"Baseline error: {e}")
            return 1.0

    def send_original_request(self, request_info):
        """Send the original request exactly as in Burp file"""
        try:
            method = request_info['method']
            url = request_info['url']
            headers = request_info['headers'].copy()
            body = request_info['body']
            
            if self.verbose:
                Logger.debug(f"Sending ORIGINAL request: {method} {url}")
            
            response = self.session.request(
                method,
                url,
                headers=headers,
                data=body,
                timeout=self.timeout,
                allow_redirects=True,  # Permitir redirects para baseline también
                verify=False
            )
            
            return response
            
        except Exception as e:
            if self.verbose:
                Logger.debug(f"Original request error: {e}")
            return None

    def test_payload(self, request_info, parameter, payload, threshold, base_time):
        """Test single payload con mejor detección"""
        if self.verbose:
            Logger.debug(f"Testing payload: {payload} on parameter: {parameter}")
        
        try:
            start_time = time.perf_counter()
            response = self.send_modified_request(request_info, parameter, payload)
            end_time = time.perf_counter()
            
            response_time = end_time - start_time
            
            if self.verbose:
                Logger.debug(f"Response time: {response_time:.2f}s | Threshold: {threshold:.2f}s | Baseline: {base_time:.2f}s")
            
            # Verificar si es TIMEOUT o si el tiempo de respuesta excede el threshold
            if response == "TIMEOUT":
                if self.verbose:
                    Logger.debug("TIMEOUT detected - potential vulnerability")
                # Considerar timeout como vulnerabilidad potencial
                self.found_vulnerabilities.append({
                    'parameter': parameter,
                    'payload': payload,
                    'response_time': self.timeout,  # Usar el timeout como tiempo
                    'base_time': base_time,
                    'time_difference': self.timeout - base_time,
                    'method': request_info['method'],
                    'url': request_info['url'],
                    'type': self.get_parameter_type(parameter),
                    'status': 'TIMEOUT'
                })
                
                print(f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.END} {request_info['url']}")
                print(f"      Parameter: {parameter} - Time: TIMEOUT (Base: {base_time:.2f}s)")
                print(f"      Payload: {payload}")
                
                return True
                
            elif response_time >= threshold:
                if self.verbose:
                    Logger.debug(f"Potential vulnerability detected! Response time: {response_time:.2f}s")
                
                # Hacer una verificación adicional para confirmar
                if self.verify_vulnerability(request_info, parameter, payload, base_time):
                    self.found_vulnerabilities.append({
                        'parameter': parameter,
                        'payload': payload,
                        'response_time': response_time,
                        'base_time': base_time,
                        'time_difference': response_time - base_time,
                        'method': request_info['method'],
                        'url': request_info['url'],
                        'type': self.get_parameter_type(parameter),
                        'status': 'DELAY'
                    })
                    
                    print(f"{Colors.RED}{Colors.BOLD}[VULN]{Colors.END} {request_info['url']}")
                    print(f"      Parameter: {parameter} - Time: {response_time:.2f}s (Base: {base_time:.2f}s)")
                    print(f"      Payload: {payload}")
                    
                    return True
            
            return False
            
        except Exception as e:
            if self.verbose:
                Logger.debug(f"Test payload error: {e}")
            return False

    def verify_vulnerability(self, request_info, parameter, payload, base_time):
        """Verificación adicional para confirmar vulnerabilidad"""
        if self.verbose:
            Logger.debug(f"Verifying vulnerability with payload: {payload}")
        
        try:
            # Enviar el payload varias veces para confirmar
            verification_times = []
            
            for i in range(2):  # 2 intentos de verificación
                start_time = time.perf_counter()
                response = self.send_modified_request(request_info, parameter, payload)
                end_time = time.perf_counter()
                
                if response and response != "TIMEOUT":
                    verification_times.append(end_time - start_time)
                
                time.sleep(1)  # Pequeña pausa entre verificaciones
            
            if verification_times:
                avg_verification_time = sum(verification_times) / len(verification_times)
                # Considerar vulnerable si el tiempo promedio es significativamente mayor al baseline
                return avg_verification_time >= base_time + 5
                
            return False
            
        except Exception as e:
            if self.verbose:
                Logger.debug(f"Verification error: {e}")
            return False

    def get_parameter_type(self, parameter):
        """Get parameter type for reporting"""
        if parameter.startswith('cookie:'):
            return 'Cookie'
        elif '.' in parameter or '[' in parameter:
            return 'JSON Parameter'
        else:
            return 'URL/Body Parameter'

    def analyze_parameter_sequential(self, request_info, parameter, payloads, threshold):
        """Analyze parameter sequentially - stops when vulnerability found"""
        if self.verbose:
            Logger.debug(f"Starting analysis for parameter: {parameter}")
        
        base_time = self.get_base_response_time(request_info, parameter)
        # Ajustar threshold para ser más sensible
        adjusted_threshold = max(threshold, base_time + 5)
        
        if self.verbose:
            Logger.debug(f"Base time: {base_time:.2f}s | Adjusted threshold: {adjusted_threshold:.2f}s")
        
        vulnerabilities_found = 0
        
        for i, payload in enumerate(payloads):
            # Progress update
            if (i + 1) % 5 == 0 or i == len(payloads) - 1:
                print(f"{Colors.CYAN}Testing {parameter}: {i + 1}/{len(payloads)}{Colors.END}", end='\r')
            
            if self.test_payload(request_info, parameter, payload, adjusted_threshold, base_time):
                vulnerabilities_found += 1
                break
        
        print()  # New line after progress
        
        return vulnerabilities_found

    def comprehensive_analysis(self, request_file=None, url=None, specific_parameter=None, wordlist_file=None, threshold=10):
        """Main analysis function for single target"""
        if request_file:
            request_info = AdvancedParameterDetector.parse_burp_request(request_file)
            Logger.info(f"Target: {request_info['url']}")
            if self.verbose:
                Logger.debug(f"Method: {request_info['method']}")
                Logger.debug(f"Headers: {request_info['headers']}")
                Logger.debug(f"Body: {request_info['body']}")
        else:
            request_info = {
                'method': 'GET',
                'url': url,
                'headers': {},
                'body': '',
                'raw_request': f"GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n"
            }
            Logger.info(f"Target: {url}")
        
        print(f"{Colors.CYAN}Method: {request_info['method']} | Threshold: {threshold}s{Colors.END}")
        print(f"{Colors.CYAN}Encoding: NONE - payloads sent exactly as in wordlist{Colors.END}")
        
        # Detect parameters AUTOMATICALLY
        parameters = AdvancedParameterDetector.detect_all_parameters(request_info)
        
        if not parameters:
            Logger.error("No parameters detected for testing")
            return []
        
        print(f"{Colors.CYAN}Detected parameters: {', '.join(parameters)}{Colors.END}")
        
        if specific_parameter:
            if specific_parameter in parameters:
                parameters = [specific_parameter]
                print(f"{Colors.CYAN}Testing specific parameter: {specific_parameter}{Colors.END}")
            else:
                Logger.error(f"Parameter '{specific_parameter}' not found")
                Logger.info(f"Available parameters: {parameters}")
                return []
        
        payloads = self.load_wordlist(wordlist_file)
        
        total_vulnerabilities = 0
        start_time = time.time()
        
        print(f"{Colors.CYAN}Testing {len(parameters)} parameters with {len(payloads)} payloads each...{Colors.END}")
        
        # TEST ALL PARAMETERS - not just the first one
        for parameter_index, parameter in enumerate(parameters):
            print(f"\n{Colors.YELLOW}[{parameter_index + 1}/{len(parameters)}] Testing parameter: {parameter}{Colors.END}")
            
            vuln_count = self.analyze_parameter_sequential(request_info, parameter, payloads, threshold)
            total_vulnerabilities += vuln_count
            
            if vuln_count > 0:
                print(f"{Colors.GREEN}  ✓ Vulnerability found in {parameter}{Colors.END}")
            else:
                print(f"{Colors.CYAN}  ✗ No vulnerability found in {parameter}{Colors.END}")
        
        analysis_time = time.time() - start_time
        
        print(f"\n{Colors.GREEN}Scan completed in {analysis_time:.2f}s - Vulnerabilities: {total_vulnerabilities}{Colors.END}")
        
        return self.found_vulnerabilities

    def bulk_analysis(self, url_list_file=None, wordlist_file=None, threshold=10):
        """Bulk analysis function for multiple URLs"""
        urls = self.load_url_list(url_list_file)
        payloads = self.load_wordlist(wordlist_file)
        
        total_vulnerabilities = 0
        start_time = time.time()
        
        print(f"{Colors.CYAN}Bulk scanning {len(urls)} URLs | Threshold: {threshold}s{Colors.END}")
        print(f"{Colors.CYAN}Encoding: NONE - payloads sent exactly as in wordlist{Colors.END}")
        
        for url_index, url in enumerate(urls):
            print(f"\n{Colors.YELLOW}[{url_index + 1}/{len(urls)}] Scanning: {url}{Colors.END}")
            
            # Create basic request info for URL
            request_info = {
                'method': 'GET',
                'url': url,
                'headers': {},
                'body': '',
                'raw_request': f"GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n"
            }
            
            # Detect parameters from URL
            parameters = AdvancedParameterDetector.detect_parameters_from_url(url)
            
            if not parameters:
                print(f"{Colors.CYAN}  No parameters found, skipping...{Colors.END}")
                continue
            
            print(f"{Colors.CYAN}  Found {len(parameters)} parameters: {', '.join(parameters)}{Colors.END}")
            
            # Test ALL parameters for this URL, ONE AT A TIME
            for param_index, parameter in enumerate(parameters):
                print(f"{Colors.CYAN}  Testing parameter {param_index + 1}/{len(parameters)}: {parameter}{Colors.END}")
                
                base_time = self.get_base_response_time(request_info, parameter)
                adjusted_threshold = max(threshold, base_time + 5)
                
                if self.verbose:
                    Logger.debug(f"Base time for {parameter}: {base_time:.2f}s | Threshold: {adjusted_threshold:.2f}s")
                
                vulnerability_found = False
                
                # Test each payload for this parameter
                for payload_index, payload in enumerate(payloads):
                    # Progress update - more clear
                    if (payload_index + 1) % 10 == 0 or payload_index == len(payloads) - 1:
                        print(f"{Colors.CYAN}    Payload {payload_index + 1}/{len(payloads)} for {parameter}{Colors.END}")
                    
                    # Test the payload
                    if self.test_payload(request_info, parameter, payload, adjusted_threshold, base_time):
                        total_vulnerabilities += 1
                        vulnerability_found = True
                        print(f"{Colors.GREEN}    ✓ Vulnerability found in {parameter} with payload {payload_index + 1}{Colors.END}")
                        break  # Stop testing this parameter after first vulnerability
                
                # Clear the progress line
                print(" " * 80, end='\r')
                
                if not vulnerability_found:
                    print(f"{Colors.CYAN}    No vulnerability found in {parameter}{Colors.END}")
        
        analysis_time = time.time() - start_time
        
        print(f"\n{Colors.GREEN}Bulk scan completed in {analysis_time:.2f}s")
        print(f"Total vulnerabilities found: {total_vulnerabilities}{Colors.END}")
        
        return self.found_vulnerabilities

def display_banner_clean():
    """Display clean BSQLi banner"""
    banner = f"""
{Colors.RED}{Colors.BOLD}
        ██████╗ ███████╗ ██████╗ ██╗     ██╗
        ██╔══██╗██╔════╝██╔═══██╗██║     ██║
        ██████╔╝███████╗██║   ██║██║     ██║
        ██╔══██╗╚════██║██║▄▄ ██║██║     ██║
        ██████╔╝███████║╚██████╔╝███████╗██║
        ╚═════╝ ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝  
          {Colors.CYAN} Blind SQL Injection Scanner{Colors.RED}
          {Colors.YELLOW}         By Mr r00t11{Colors.RED}
{Colors.END}
    """
    print(banner)

def generate_report(vulnerabilities, output_file=None):
    """Generate detailed report"""
    if not vulnerabilities:
        print(f"{Colors.GREEN}No vulnerabilities found{Colors.END}")
        return
    
    print(f"\n{Colors.RED}{Colors.BOLD}VULNERABILITIES FOUND:{Colors.END}")
    print(f"{Colors.RED}{'='*50}{Colors.END}")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n{Colors.RED}{i}. {vuln['url']}{Colors.END}")
        print(f"   Parameter: {vuln['parameter']} ({vuln['type']})")
        print(f"   Payload: {vuln['payload']}")
        if vuln.get('status') == 'TIMEOUT':
            print(f"   Time: TIMEOUT (> {vuln['response_time']}s)")
        else:
            print(f"   Time: {vuln['response_time']:.2f}s (baseline: {vuln['base_time']:.2f}s)")
        print(f"   Increase: +{vuln['time_difference']:.2f}s")
    
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("BLIND SQL INJECTION BULK SCAN REPORT\n")
                f.write("=" * 40 + "\n\n")
                f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
                
                for vuln in vulnerabilities:
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    if vuln.get('status') == 'TIMEOUT':
                        f.write(f"Response Time: TIMEOUT (> {vuln['response_time']}s)\n")
                    else:
                        f.write(f"Response Time: {vuln['response_time']:.2f}s\n")
                    f.write(f"Baseline: {vuln['base_time']:.2f}s\n")
                    f.write(f"Increase: +{vuln['time_difference']:.2f}s\n")
                    f.write("-" * 50 + "\n")
            
            print(f"{Colors.GREEN}Report saved: {output_file}{Colors.END}")
        except Exception as e:
            Logger.error(f"Error saving report: {e}")

def main():
    display_banner_clean()
    
    parser = argparse.ArgumentParser(description='BSQLi - Blind SQL Injection Scanner')
    
    # Create mutually exclusive group for target selection
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single target URL')
    target_group.add_argument('-r', '--request', help='Burp Suite request file')
    target_group.add_argument('-l', '--list', help='File with list of URLs to scan')
    
    parser.add_argument('-p', '--parameter', help='Specific parameter to test (single target only)')
    parser.add_argument('-w', '--wordlist', required=True, help='Payload wordlist')
    parser.add_argument('-t', '--threshold', type=float, default=10.0, help='Time threshold (default: 10s)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--timeout', type=float, default=30, help='Request timeout (default: 30s)')
    parser.add_argument('--encoding', help='Payload encoding type')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode for debugging')
    
    args = parser.parse_args()
    
    # Validate encoding parameter
    valid_encodings = [None, 'none', 'base64', 'url', 'html', 'hex', 'unicode', 'doubleurl', 'base64url']
    if args.encoding and args.encoding.lower() not in [e for e in valid_encodings if e is not None]:
        Logger.error(f"Invalid encoding type: {args.encoding}")
        sys.exit(1)
    
    analyzer = EnhancedBSQLIAnalyzer(timeout=args.timeout, encoding=args.encoding, verbose=args.verbose)
    
    if args.verbose:
        Logger.info("Verbose mode enabled - showing detailed debugging information")
    
    if args.list:
        # Bulk analysis mode
        vulnerabilities = analyzer.bulk_analysis(
            url_list_file=args.list,
            wordlist_file=args.wordlist,
            threshold=args.threshold
        )
    else:
        # Single target analysis mode (including -r for Burp files)
        vulnerabilities = analyzer.comprehensive_analysis(
            request_file=args.request,
            url=args.url,
            specific_parameter=args.parameter,
            wordlist_file=args.wordlist,
            threshold=args.threshold
        )
    
    generate_report(vulnerabilities, args.output)

if __name__ == "__main__":
    main()
