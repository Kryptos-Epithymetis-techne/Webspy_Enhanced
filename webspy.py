#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import urllib.parse
import threading
import time
import re
from bs4 import BeautifulSoup
import json
from datetime import datetime
import webbrowser
import os
import subprocess
import platform
import base64
import ssl
import socket
import hashlib
import xml.etree.ElementTree as ET
from urllib.robotparser import RobotFileParser
import concurrent.futures
import queue
import logging
import sys
import shutil

class WebSpyEnhanced:
    def __init__(self, root):
        self.root = root
        self.root.title("WebSpy Enhanced - Advanced Security Testing Suite v2.0")
        
        # Detect platform
        self.current_platform = platform.system().lower()
        self.is_windows = self.current_platform == 'windows'
        self.is_linux = self.current_platform == 'linux'
        self.is_macos = self.current_platform == 'darwin'
        self.is_raspberry_pi = self.is_linux and self._detect_raspberry_pi()
        
        # Setup logging
        self.setup_logging()
        
        # Optimize window size based on platform and screen size
        self.setup_window_size()
            
        self.root.configure(bg='#2b2b2b')
        
        # Thread management
        self.scan_threads = []
        self.stop_scanning = threading.Event()
        
        # Results queue for thread-safe updates
        self.results_queue = queue.Queue()
        
        # Performance monitoring
        self.scan_start_time = None
        self.urls_tested = 0
        
        # Configuration storage
        self.config_file = os.path.expanduser("~/.webspy_config.json")
        self.load_configuration()
        
        # Tool availability checking
        self.available_tools = self.check_tool_availability()
        
        # Configure style for dark theme optimized for platform
        self.setup_style()
        self.setup_ui()
        
        # Add system info
        self.add_system_info()
        
        # Start result processor
        self.process_results()
        
        # Validate API keys
       # self.validate_api_keys()
        
    def _detect_raspberry_pi(self):
        """Check if running on Raspberry Pi"""
        try:
            if os.path.exists('/proc/device-tree/model'):
                with open('/proc/device-tree/model', 'r') as f:
                    return 'raspberry pi' in f.read().lower()
            return False
        except:
            return False
        
    def setup_window_size(self):
        """Setup window size based on platform and screen size"""
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Different default sizes based on platform
        if self.is_raspberry_pi:
            # Smaller window for Raspberry Pi
            self.root.geometry("1000x700")
        elif self.is_windows:
            # Medium window for Windows
            self.root.geometry("1200x800")
        elif self.is_macos:
            # Slightly larger for macOS
            self.root.geometry("1400x900")
        else:
            # Default for Linux and others
            if screen_width <= 1920:
                self.root.geometry("1200x800")
            else:
                self.root.geometry("1400x900")
    
    def check_tool_availability(self):
        """Check which security tools are available on the system"""
        tools = {
            'nmap': False,
            'nikto': False,
            'whois': False,
            'traceroute': False,
            'sqlmap': False,
            'gobuster': False,
            'hydra': False
        }
        
        # Check each tool
        for tool in tools.keys():
            tools[tool] = self.is_tool_available(tool)
            
        return tools
    
    def is_tool_available(self, tool_name):
        """Check if a specific tool is available on the system"""
        if self.is_windows:
            # On Windows, check if the tool is in PATH
            return shutil.which(tool_name) is not None
        else:
            # On Unix-like systems, use which command
            try:
                subprocess.run(['which', tool_name], 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL, 
                              check=True)
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False
    
    def setup_logging(self):
        """Setup logging system with platform-specific paths"""
        if self.is_windows:
            log_dir = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'WebSpy', 'logs')
        else:
            log_dir = os.path.expanduser("~/.webspy_logs")
            
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"webspy_{datetime.now().strftime('%Y%m%d')}.log")
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_configuration(self):
        """Load saved configuration with platform-specific defaults"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.shodan_api_key = config.get('shodan_api_key', '')
                    self.github_token = config.get('github_token', '')
                    self.censys_api_id = config.get('censys_api_id', '')
                    self.censys_secret = config.get('censys_secret', '')
                    self.virustotal_api_key = config.get('virustotal_api_key', '')
                    self.custom_wordlists = config.get('custom_wordlists', {})
                    self.scan_settings = config.get('scan_settings', {})
            else:
                # Default values
                self.shodan_api_key = ""
                self.github_token = ""
                self.censys_api_id = ""
                self.censys_secret = ""
                self.virustotal_api_key = ""
                self.custom_wordlists = {}
                
                # Platform-specific default settings
                if self.is_raspberry_pi:
                    # Fewer threads and longer delays for Raspberry Pi
                    self.scan_settings = {
                        'timeout': 15,
                        'threads': 3,
                        'delay': 1.0,
                        'user_agent': 'WebSpy-Enhanced/2.0 (Raspberry Pi)'
                    }
                else:
                    # More aggressive settings for other platforms
                    self.scan_settings = {
                        'timeout': 10,
                        'threads': 10,
                        'delay': 0.2,
                        'user_agent': 'WebSpy-Enhanced/2.0'
                    }
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            # Set defaults
            self.shodan_api_key = ""
            self.github_token = ""
            self.censys_api_id = ""
            self.censys_secret = ""
            self.virustotal_api_key = ""
            self.custom_wordlists = {}
            self.scan_settings = {
                'timeout': 10,
                'threads': 5,
                'delay': 0.5,
                'user_agent': 'WebSpy-Enhanced/2.0'
            }
    
    def save_configuration(self):
        """Save current configuration"""
        try:
            config = {
                'shodan_api_key': self.shodan_api_key,
                'github_token': self.github_token,
                'censys_api_id': self.censys_api_id,
                'censys_secret': self.censys_secret,
                'virustotal_api_key': self.virustotal_api_key,
                'custom_wordlists': self.custom_wordlists,
                'scan_settings': self.scan_settings
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
    
    def validate_api_keys(self):
        """Validate that required API keys are present"""
       # missing_apis = []
        
       # if not self.shodan_api_key:
        #    missing_apis.append("Shodan")
      #  if not self.censys_api_id or not self.censys_secret:
        #    missing_apis.append("Censys")
       # if not self.virustotal_api_key:
         #   missing_apis.append("VirusTotal")
      #  if not self.github_token:
      #      missing_apis.append("GitHub")
        
       # if missing_apis:
       #     message = "The following API keys are missing:\n" + #"\n".join(missing_apis)
       #     message += "\n\nSome features will not work without these #keys."
       #     messagebox.showwarning("Missing API Keys", message)
        
    def setup_style(self):
    """Setup optimized styling for different platforms"""
    style = ttk.Style()
    
    # Use appropriate theme for each platform
    if self.is_windows:
        style.theme_use('vista')
    elif self.is_macos:
        style.theme_use('aqua')
    else:
        style.theme_use('clam')
    
    # Dark theme colors
    style.configure('TNotebook', background='#2b2b2b')
    style.configure('TNotebook.Tab', background='#404040', foreground='white', padding=[8, 4])
    style.map('TNotebook.Tab', background=[('selected', '#0078d4')])
    style.configure('TFrame', background='#2b2b2b')
    style.configure('TLabel', background='#2b2b2b', foreground='white')
    style.configure('Dark.TButton', 
                   background='#0078d4',                   
                   foreground='white', 
                   borderwidth=1,
                   focusthickness=3,
                   focuscolor='#0078d4')
    style.map('Dark.TButton',
              background=[('active', '#005a9e'), ('!active', '#0078d4')],
              foreground=[('active', 'white'), ('pressed', 'white'), ('!active', 'white')],
              relief=[('pressed', 'sunken'), ('!pressed', 'raised')])

    # Progress bar style
    style.configure('TProgressbar', background='#0078d4')

    # Configure combobox style
    style.configure('TCombobox', 
                   fieldbackground='#1e1e1e', 
                   background='#0078d4',
                   foreground='white',
                   arrowcolor='white')

    # Configure entry fields
    style.configure('TEntry',
                   fieldbackground='#1e1e1e',
                   foreground='white',
                   insertcolor='white')
        
    def setup_ui(self):
        # Header with platform indicator
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        platform_icon = "🍓" if self.is_raspberry_pi else "🖥️" if self.is_windows else "🐧" if self.is_linux else "🍎"
        platform_name = "Raspberry Pi" if self.is_raspberry_pi else "Windows" if self.is_windows else "Linux" if self.is_linux else "macOS"
        
        title_label = ttk.Label(header_frame, 
                               text=f"🛡️ WebSpy Enhanced v2.0 - {platform_name} {platform_icon}", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(side='left')
        
        # Control buttons
        control_frame = ttk.Frame(header_frame)
        control_frame.pack(side='right')
        
        ttk.Button(control_frame, text="⚙️ Settings", 
                   style='Dark.TButton',
                  command=self.show_settings_dialog).pack(side='left', padx=2)
        ttk.Button(control_frame, text="📊 Reports", 
                  command=self.show_reports_dialog).pack(side='left', padx=2)
        ttk.Button(control_frame, text="🔧 Tools", 
                  command=self.show_tools_menu).pack(side='left', padx=2)
        ttk.Button(control_frame, text="ℹ️ System Info", 
                  command=self.show_system_info).pack(side='left', padx=2)
        
        # URL Input with validation
        url_frame = ttk.Frame(self.root)
        url_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(url_frame, text="Target URL:").pack(side='left')
        self.url_var = tk.StringVar(value="https://example.com")
        self.url_var.trace('w', self.validate_url)
        self.url_entry = ttk.Entry(url_frame, textvariable=self.url_var, width=50)
        self.url_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        # URL validation indicator
        self.url_status = ttk.Label(url_frame, text="", foreground='green')
        self.url_status.pack(side='left', padx=2)
        
        # Scan controls
        scan_controls = ttk.Frame(url_frame)
        scan_controls.pack(side='right')
        
        self.scan_btn = ttk.Button(scan_controls, text="🔍 Full Scan", command=self.start_scan)
        self.scan_btn.pack(side='left', padx=2)
        
        self.stop_btn = ttk.Button(scan_controls, text="⏹️ Stop", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=2)
        
        # Quick scan options
        quick_frame = ttk.Frame(self.root)
        quick_frame.pack(fill='x', padx=10, pady=2)
        
        ttk.Button(quick_frame, text="🚀 Quick Scan", command=self.quick_scan).pack(side='left', padx=2)
        ttk.Button(quick_frame, text="🔍 Directory Fuzz", command=self.directory_fuzz).pack(side='left', padx=2)
        ttk.Button(quick_frame, text="🔐 SSL Check", command=self.ssl_quick_check).pack(side='left', padx=2)
        
        # Only show Nikto button if available
        if self.available_tools['nikto']:
            ttk.Button(quick_frame, text="📊 Nikto Scan", command=self.nikto_scan).pack(side='left', padx=2)
        
        ttk.Button(quick_frame, text="🌐 OSINT", command=self.osint_scan).pack(side='left', padx=2)
        
        # Progress and status
        progress_frame = ttk.Frame(self.root)
        progress_frame.pack(fill='x', padx=10, pady=2)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.pack(fill='x')
        
        # Status bar
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill='x', padx=10, pady=2)
        
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.pack(side='left')
        
        self.progress_detail = ttk.Label(self.status_frame, text="")
        self.progress_detail.pack(side='left', padx=20)
        
        # Platform-specific status indicators
        if self.is_raspberry_pi:
            self.temp_label = ttk.Label(self.status_frame, text="")
            self.temp_label.pack(side='right')
        
        self.performance_label = ttk.Label(self.status_frame, text="")
        self.performance_label.pack(side='right', padx=10)
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.setup_tabs()
        
        # Start monitoring
        if self.is_raspberry_pi:
            self.monitor_pi_performance()
        else:
            self.monitor_system_performance()
        
    def validate_url(self, *args):
        """Validate URL format"""
        url = self.url_var.get()
        if not url:
            self.url_status.config(text="", foreground='red')
            return
            
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                self.url_status.config(text="✓", foreground='green')
            else:
                self.url_status.config(text="⚠", foreground='orange')
        except:
            self.url_status.config(text="✗", foreground='red')
    
    def setup_tabs(self):
        """Setup all tabs with enhanced tools"""
        tab_height = 18
        
        # Overview Tab with real-time updates
        self.overview_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.overview_frame, text="📊 Overview")
        
        overview_top = ttk.Frame(self.overview_frame)
        overview_top.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(overview_top, text="📋 Save Report", command=self.save_report).pack(side='left', padx=5)
        ttk.Button(overview_top, text="🔄 Refresh", command=self.refresh_overview).pack(side='left')
        
        self.overview_text = scrolledtext.ScrolledText(
            self.overview_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.overview_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Enhanced Directory Fuzzing Tab
        self.fuzz_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.fuzz_frame, text="📂 Dir Fuzzing")
        
        fuzz_controls = ttk.Frame(self.fuzz_frame)
        fuzz_controls.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(fuzz_controls, text="Wordlist:").pack(side='left')
        self.wordlist_var = tk.StringVar(value="common")
        wordlist_combo = ttk.Combobox(fuzz_controls, textvariable=self.wordlist_var, 
                                     values=["common", "medium", 'large', "custom"], width=10)
        wordlist_combo.pack(side='left', padx=5)
        
        ttk.Label(fuzz_controls, text="Threads:").pack(side='left', padx=5)
        self.fuzz_threads_var = tk.StringVar(value=str(self.scan_settings.get('threads', 5)))
        thread_spin = ttk.Spinbox(fuzz_controls, from_=1, to=20, width=5, textvariable=self.fuzz_threads_var)
        thread_spin.pack(side='left', padx=2)
        
        ttk.Button(fuzz_controls, text="📁 Load Custom", 
                  command=self.load_custom_wordlist).pack(side='left', padx=5)
        ttk.Button(fuzz_controls, text="🔍 Start Fuzzing", 
                  command=self.start_directory_fuzzing).pack(side='left', padx=5)
        
        self.fuzz_text = scrolledtext.ScrolledText(
            self.fuzz_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.fuzz_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Enhanced OSINT Tab (combines multiple intelligence sources)
        self.osint_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.osint_frame, text="🌐 OSINT")
        
        osint_controls = ttk.Frame(self.osint_frame)
        osint_controls.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(osint_controls, text="🔍 Shodan", command=self.shodan_lookup_wrapper).pack(side='left', padx=2)
        ttk.Button(osint_controls, text="🔐 Censys", command=self.censys_lookup).pack(side='left', padx=2)
        ttk.Button(osint_controls, text="🦠 VirusTotal", command=self.virustotal_lookup).pack(side='left', padx=2)
        ttk.Button(osint_controls, text="📋 CT Logs", command=self.cert_transparency_lookup_wrapper).pack(side='left', padx=2)
        ttk.Button(osint_controls, text="🐙 GitHub", command=self.github_dork_search_wrapper).pack(side='left', padx=2)
        
        self.osint_text = scrolledtext.ScrolledText(
            self.osint_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.osint_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Vulnerability Assessment Tab
        self.vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_frame, text="🔍 Vulnerabilities")
        
        vuln_controls = ttk.Frame(self.vuln_frame)
        vuln_controls.pack(fill='x', padx=5, pady=5)
        
        # Only show external tool buttons if available
        if self.available_tools['nikto']:
            ttk.Button(vuln_controls, text="🛡️ Nikto Scan", command=self.start_nikto_scan).pack(side='left', padx=2)
        
        ttk.Button(vuln_controls, text="💉 SQL Test", command=self.test_sql_injection_wrapper).pack(side='left', padx=2)
        ttk.Button(vuln_controls, text="🔗 XSS Test", command=self.test_xss).pack(side='left', padx=2)
        ttk.Button(vuln_controls, text="📂 LFI Test", command=self.test_lfi).pack(side='left', padx=2)
        ttk.Button(vuln_controls, text="⚡ CRLF Test", command=self.test_crlf).pack(side='left', padx=2)
        
        self.vuln_text = scrolledtext.ScrolledText(
            self.vuln_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.vuln_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Network Analysis Tab
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="🌐 Network")
        
        network_controls = ttk.Frame(self.network_frame)
        network_controls.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(network_controls, text="🔍 Port Scan", command=self.port_scan).pack(side='left', padx=2)
        ttk.Button(network_controls, text="📡 Traceroute", command=self.traceroute).pack(side='left', padx=2)
        
        # Only show whois if available
        if self.available_tools['whois']:
            ttk.Button(network_controls, text="🏠 Whois", command=self.whois_lookup).pack(side='left', padx=2)
            
        ttk.Button(network_controls, text="🌍 Geolocation", command=self.geo_lookup).pack(side='left', padx=2)
        
        self.network_text = scrolledtext.ScrolledText(
            self.network_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.network_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Keep existing specialized tabs but enhance them
        self.setup_existing_enhanced_tabs()
        
    def setup_existing_enhanced_tabs(self):
        """Setup enhanced versions of existing tabs"""
        tab_height = 18
        
        # Enhanced Robots.txt Tab with sitemap analysis
        self.robots_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.robots_frame, text="🤖 Robots & Sitemaps")
        
        robots_controls = ttk.Frame(self.robots_frame)
        robots_controls.pack(fill='x', padx=5, pady=2)
        
        ttk.Button(robots_controls, text="🤖 Check Robots", command=self.check_robots_wrapper).pack(side='left', padx=2)
        ttk.Button(robots_controls, text="🗺️ Find Sitemaps", command=self.find_sitemaps).pack(side='left', padx=2)
        ttk.Button(robots_controls, text="📄 Security.txt", command=self.check_security_txt).pack(side='left', padx=2)
        
        self.robots_text = scrolledtext.ScrolledText(
            self.robots_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.robots_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Enhanced Security Headers Tab with OWASP compliance
        self.security_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.security_frame, text="🛡️ Security Headers")
        
        security_controls = ttk.Frame(self.security_frame)
        security_controls.pack(fill='x', padx=5, pady=2)
        
        ttk.Button(security_controls, text="🔍 Analyze Headers", command=self.analyze_security_headers_wrapper).pack(side='left', padx=2)
        ttk.Button(security_controls, text="📊 OWASP Check", command=self.owasp_header_check).pack(side='left', padx=2)
        ttk.Button(security_controls, text="⚡ Security Score", command=self.calculate_security_score).pack(side='left', padx=2)
        
        self.security_text = scrolledtext.ScrolledText(
            self.security_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.security_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Enhanced SSL/TLS Analysis Tab
        self.ssl_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ssl_frame, text="🔐 SSL/TLS")
        
        ssl_controls = ttk.Frame(self.ssl_frame)
        ssl_controls.pack(fill='x', padx=5, pady=2)
        
        ttk.Button(ssl_controls, text="🔍 SSL Analysis", command=self.analyze_ssl_tls_wrapper).pack(side='left', padx=2)
        ttk.Button(ssl_controls, text="🏆 SSL Labs", command=self.ssl_labs_check).pack(side='left', padx=2)
        ttk.Button(ssl_controls, text="🔐 Cipher Check", command=self.cipher_analysis).pack(side='left', padx=2)
        
        self.ssl_text = scrolledtext.ScrolledText(
            self.ssl_frame, bg='#1e1e1e', fg='white', 
            height=tab_height-2, font=('Consolas', 9))
        self.ssl_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    # Enhanced API integration methods
    def censys_lookup(self):
        """Perform Censys lookup"""
        if not self.censys_api_id or not self.censys_secret:
            self.update_osint_text("❌ Censys API credentials not configured\n")
            return
        
        url = self.url_var.get().strip()
        domain = urllib.parse.urlparse(url).netloc
        
        thread = threading.Thread(target=self._censys_lookup_impl, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _censys_lookup_impl(self, domain):
        """Censys lookup implementation"""
        try:
            import socket
            ip = socket.gethostbyname(domain)
            
            auth = (self.censys_api_id, self.censys_secret)
            headers = {'User-Agent': self.scan_settings['user_agent']}
            
            url = f"https://censys.io/api/v1/search/ipv4"
            data = {"query": ip, "page": 1, "fields": ["ip", "protocols", "location.country"]}
            
            response = self.safe_request(url, method='POST', json=data, auth=auth, headers=headers)
            
            if response and response.status_code == 200:
                data = response.json()
                result = f"🔍 CENSYS LOOKUP - {domain}\n{'='*40}\n\n"
                result += f"IP Address: {ip}\n\n"
                
                for host in data.get('results', []):
                    result += f"Protocols: {', '.join(host.get('protocols', []))}\n"
                    location = host.get('location', {})
                    if location:
                        result += f"Country: {location.get('country', 'Unknown')}\n"
                
                self.update_osint_text(result)
            else:
                error_msg = f"❌ Censys API error: {response.status_code if response else 'No response'}\n"
                self.update_osint_text(error_msg)
                
        except Exception as e:
            self.update_osint_text(f"❌ Censys lookup error: {str(e)}\n")
    
    def virustotal_lookup(self):
        """VirusTotal domain/IP lookup"""
        if not self.virustotal_api_key:
            self.update_osint_text("❌ VirusTotal API key not configured\n")
            return
        
        url = self.url_var.get().strip()
        domain = urllib.parse.urlparse(url).netloc
        
        thread = threading.Thread(target=self._virustotal_lookup_impl, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _virustotal_lookup_impl(self, domain):
        """VirusTotal lookup implementation"""
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            
            # Domain lookup
            domain_id = base64.urlsafe_b64encode(domain.encode()).decode().strip('=')
            url = f"https://www.virustotal.com/api/v3/domains/{domain_id}"
            
            response = self.safe_request(url, headers=headers)
            
            if response and response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                result = f"🦠 VIRUSTOTAL LOOKUP - {domain}\n{'='*40}\n\n"
                
                last_analysis = attributes.get('last_analysis_stats', {})
                if last_analysis:
                    result += f"Security Scan Results:\n"
                    result += f"  Clean: {last_analysis.get('harmless', 0)}\n"
                    result += f"  Suspicious: {last_analysis.get('suspicious', 0)}\n"
                    result += f"  Malicious: {last_analysis.get('malicious', 0)}\n\n"
                
                categories = attributes.get('categories', {})
                if categories:
                    result += f"Categories: {', '.join(categories.values())}\n"
                
                reputation = attributes.get('reputation', 0)
                result += f"Reputation Score: {reputation}\n"
                
                self.update_osint_text(result)
            else:
                error_msg = f"❌ VirusTotal API error: {response.status_code if response else 'No response'}\n"
                self.update_osint_text(error_msg)
                
        except Exception as e:
            self.update_osint_text(f"❌ VirusTotal lookup error: {str(e)}\n")
    
    # Enhanced vulnerability testing methods
    def test_xss(self):
        """Test for XSS vulnerabilities"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._test_xss_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _test_xss_impl(self, url):
        """XSS testing implementation"""
        try:
            result = "🔗 XSS VULNERABILITY TEST\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            # XSS payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')></iframe>"
            ]
            
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                result += "❌ No parameters found for XSS testing\n"
                result += "💡 XSS testing requires URLs with parameters\n"
                self.update_vuln_text(result)
                return
            
            vulnerabilities = []
            
            for param_name in params.keys():
                result += f"\n🎯 Testing parameter: {param_name}\n"
                
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.safe_request(test_url)
                        
                        if response and payload in response.text:
                            vuln_info = f"Reflected XSS in {param_name} with payload: {payload}"
                            vulnerabilities.append(vuln_info)
                            result += f"🚨 POTENTIAL XSS: {payload[:30]}...\n"
                            break
                            
                    except Exception as e:
                        continue
            
            # Summary
            result += f"\n📊 XSS TEST SUMMARY:\n"
            result += f"Parameters tested: {len(params)}\n"
            result += f"Potential vulnerabilities: {len(vulnerabilities)}\n"
            
            if vulnerabilities:
                result += "\n🚨 POTENTIAL XSS VULNERABILITIES:\n"
                for vuln in vulnerabilities:
                    result += f"   • {vuln}\n"
            else:
                result += "\n✅ No obvious XSS vulnerabilities found\n"
            
            self.update_vuln_text(result)
            
        except Exception as e:
            error_msg = f"❌ XSS testing error: {str(e)}\n"
            self.update_vuln_text(error_msg)
    
    def test_lfi(self):
        """Test for Local File Inclusion vulnerabilities"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._test_lfi_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _test_lfi_impl(self, url):
        """LFI testing implementation"""
        try:
            result = "📂 LOCAL FILE INCLUSION TEST\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            # LFI payloads
            payloads = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../etc/shadow",
                "../../../proc/version",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd"
            ]
            
            # Indicators of successful LFI
            success_indicators = [
                "root:", "daemon:", "bin:", "sys:",  # /etc/passwd
                "localhost", "127.0.0.1",  # hosts file
                "Linux version", "Darwin",  # /proc/version
                "[boot loader]", "[operating systems]"  # Windows boot.ini
            ]
            
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                result += "❌ No parameters found for LFI testing\n"
                self.update_vuln_text(result)
                return
            
            vulnerabilities = []
            
            for param_name in params.keys():
                result += f"\n🎯 Testing parameter: {param_name}\n"
                
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.safe_request(test_url)
                        
                        if response:
                            for indicator in success_indicators:
                                if indicator in response.text:
                                    vuln_info = f"LFI in {param_name} with payload: {payload}"
                                    vulnerabilities.append(vuln_info)
                                    result += f"🚨 POTENTIAL LFI: {payload[:30]}...\n"
                                    break
                                    
                    except Exception as e:
                        continue
            
            result += f"\n📊 LFI TEST SUMMARY:\n"
            result += f"Vulnerabilities found: {len(vulnerabilities)}\n"
            
            if vulnerabilities:
                result += "\n🚨 POTENTIAL LFI VULNERABILITIES:\n"
                for vuln in vulnerabilities:
                    result += f"   • {vuln}\n"
            else:
                result += "\n✅ No obvious LFI vulnerabilities found\n"
            
            self.update_vuln_text(result)
            
        except Exception as e:
            error_msg = f"❌ LFI testing error: {str(e)}\n"
            self.update_vuln_text(error_msg)
    
    def test_crlf(self):
        """Test for CRLF injection vulnerabilities"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._test_crlf_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _test_crlf_impl(self, url):
        """CRLF injection testing implementation"""
        try:
            result = "⚡ CRLF INJECTION TEST\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            # CRLF payloads
            payloads = [
                "%0d%0aSet-Cookie: test=test",
                "%0a%0dSet-Cookie: test=test",
                "%0d%0aLocation: http://evil.com",
                "%0aContent-Length: 0%0d%0a%0d%0a",
                "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('CRLF')</script>",
                "\r\nSet-Cookie: injected=true"
            ]
            
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                result += "❌ No parameters found for CRLF testing\n"
                self.update_vuln_text(result)
                return
            
            vulnerabilities = []
            
            for param_name in params.keys():
                result += f"\n🎯 Testing parameter: {param_name}\n"
                
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = urllib.parse.urlencode(test_params, doseq=True, safe='%')
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.safe_request(test_url)
                        
                        # Check if CRLF injection worked by looking at headers
                        if response and ('test=test' in str(response.headers) or 'injected=true' in str(response.headers)):
                            vuln_info = f"CRLF injection in {param_name}"
                            vulnerabilities.append(vuln_info)
                            result += f"🚨 POTENTIAL CRLF: Header injection detected\n"
                            break
                            
                    except Exception as e:
                        continue
            
            result += f"\n📊 CRLF TEST SUMMARY:\n"
            result += f"Vulnerabilities found: {len(vulnerabilities)}\n"
            
            if vulnerabilities:
                result += "\n🚨 POTENTIAL CRLF VULNERABILITIES:\n"
                for vuln in vulnerabilities:
                    result += f"   • {vuln}\n"
            else:
                result += "\n✅ No obvious CRLF vulnerabilities found\n"
            
            self.update_vuln_text(result)
            
        except Exception as e:
            error_msg = f"❌ CRLF testing error: {str(e)}\n"
            self.update_vuln_text(error_msg)
    
    # Enhanced network analysis methods
    def port_scan(self):
        """Basic port scanning"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        
        # Use built-in port scanner if nmap is not available
        if not self.available_tools['nmap']:
            thread = threading.Thread(target=self._port_scan_impl, args=(domain,))
            thread.daemon = True
            thread.start()
        else:
            thread = threading.Thread(target=self._nmap_port_scan_impl, args=(domain,))
            thread.daemon = True
            thread.start()
    
    def _port_scan_impl(self, domain):
        """Port scan implementation"""
        try:
            result = "🔍 PORT SCAN\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
            
            open_ports = []
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result_code = sock.connect_ex((domain, port))
                    sock.close()
                    
                    if result_code == 0:
                        open_ports.append(port)
                        result += f"✅ Port {port}: Open\n"
                    else:
                        result += f"❌ Port {port}: Closed\n"
                        
                except Exception:
                    result += f"❓ Port {port}: Error\n"
            
            result += f"\n📊 SCAN SUMMARY:\n"
            result += f"Open ports: {len(open_ports)}\n"
            result += f"Ports scanned: {len(common_ports)}\n"
            
            self.update_network_text(result)
            
        except Exception as e:
            error_msg = f"❌ Port scan error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    def _nmap_port_scan_impl(self, domain):
        """Nmap port scan implementation"""
        try:
            result = "🔍 NMAP PORT SCAN\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            # Run nmap with common options
            cmd = ["nmap", "-sS", "-T4", "-F", domain]  # Fast SYN scan
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if stdout:
                result += stdout
            if stderr:
                result += f"\nErrors:\n{stderr}"
            
            self.update_network_text(result)
            
        except subprocess.TimeoutExpired:
            error_msg = "❌ Nmap scan timeout\n"
            self.update_network_text(error_msg)
        except Exception as e:
            error_msg = f"❌ Nmap scan error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    def traceroute(self):
        """Perform traceroute"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        
        # Use appropriate traceroute command for the platform
        if self.is_windows:
            cmd = ["tracert", domain]
        else:
            cmd = ["traceroute", domain]
            
        thread = threading.Thread(target=self._traceroute_impl, args=(cmd, domain))
        thread.daemon = True
        thread.start()
    
    def _traceroute_impl(self, cmd, domain):
        """Traceroute implementation"""
        try:
            result = "📡 TRACEROUTE\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=120)  # 2 minute timeout
            
            if stdout:
                result += stdout
            if stderr:
                result += f"\nErrors:\n{stderr}"
            
            self.update_network_text(result)
            
        except subprocess.TimeoutExpired:
            error_msg = "❌ Traceroute timeout\n"
            self.update_network_text(error_msg)
        except Exception as e:
            error_msg = f"❌ Traceroute error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        
        # Use whois command if available, otherwise use web API
        if self.available_tools['whois']:
            thread = threading.Thread(target=self._whois_impl, args=(domain,))
            thread.daemon = True
            thread.start()
        else:
            thread = threading.Thread(target=self._whois_web_impl, args=(domain,))
            thread.daemon = True
            thread.start()
    
    def _whois_impl(self, domain):
        """WHOIS implementation using system command"""
        try:
            result = "🏠 WHOIS LOOKUP\n" + "="*40 + "\n\n"
            result += f"Domain: {domain}\n\n"
            
            try:
                process = subprocess.Popen(["whois", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate(timeout=30)
                
                if stdout:
                    result += stdout
                else:
                    result += "❌ No WHOIS data available\n"
                    
            except subprocess.TimeoutExpired:
                result += "❌ WHOIS lookup timeout\n"
            except FileNotFoundError:
                result += "❌ WHOIS command not available\n"
                result += "💡 Using web-based lookup instead\n"
                self._whois_web_impl(domain)
                return
            
            self.update_network_text(result)
            
        except Exception as e:
            error_msg = f"❌ WHOIS error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    def _whois_web_impl(self, domain):
        """WHOIS implementation using web API"""
        try:
            result = "🏠 WHOIS LOOKUP (Web API)\n" + "="*40 + "\n\n"
            result += f"Domain: {domain}\n\n"
            
            # Use a free WHOIS API
            whois_url = f"https://www.whois.com/wwhois/{domain}"
            response = self.safe_request(whois_url)
            
            if response and response.status_code == 200:
                # Extract WHOIS data from the response
                soup = BeautifulSoup(response.text, 'html.parser')
                whois_data = soup.find('pre', {'class': 'df-raw'})
                
                if whois_data:
                    result += whois_data.text
                else:
                    result += "❌ Could not extract WHOIS data from web response\n"
                    result += f"💡 Visit {whois_url} for manual lookup\n"
            else:
                result += f"❌ WHOIS API error: {response.status_code if response else 'No response'}\n"
                result += f"💡 Visit https://www.whois.com/whois/{domain} for manual lookup\n"
            
            self.update_network_text(result)
            
        except Exception as e:
            error_msg = f"❌ WHOIS web lookup error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    def geo_lookup(self):
        """Geolocation lookup"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        thread = threading.Thread(target=self._geo_lookup_impl, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _geo_lookup_impl(self, domain):
        """Geolocation implementation"""
        try:
            result = "🌍 GEOLOCATION LOOKUP\n" + "="*40 + "\n\n"
            result += f"Domain: {domain}\n\n"
            
            # Get IP address
            import socket
            ip = socket.gethostbyname(domain)
            result += f"IP Address: {ip}\n\n"
            
            # Use free geolocation API
            geo_url = f"http://ip-api.com/json/{ip}"
            response = self.safe_request(geo_url)
            
            if response and response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result += f"Country: {data.get('country', 'Unknown')}\n"
                    result += f"Region: {data.get('regionName', 'Unknown')}\n"
                    result += f"City: {data.get('city', 'Unknown')}\n"
                    result += f"ISP: {data.get('isp', 'Unknown')}\n"
                    result += f"Organization: {data.get('org', 'Unknown')}\n"
                    result += f"Timezone: {data.get('timezone', 'Unknown')}\n"
                    result += f"Coordinates: {data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}\n"
                else:
                    result += "❌ Geolocation lookup failed\n"
            else:
                result += f"❌ Geolocation API error: {response.status_code if response else 'No response'}\n"
            
            self.update_network_text(result)
            
        except Exception as e:
            error_msg = f"❌ Geolocation error: {str(e)}\n"
            self.update_network_text(error_msg)
    
    # Enhanced configuration and reporting methods
    def show_settings_dialog(self):
        """Show comprehensive settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("WebSpy Enhanced - Settings")
        settings_window.geometry("600x500")
        settings_window.configure(bg='#2b2b2b')
        
        # Create notebook for different setting categories
        settings_notebook = ttk.Notebook(settings_window)
        settings_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # API Keys tab
        api_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(api_frame, text="API Keys")
        
        ttk.Label(api_frame, text="API Configuration", font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Shodan API
        shodan_frame = ttk.Frame(api_frame)
        shodan_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(shodan_frame, text="Shodan API Key:").pack(anchor='w')
        self.shodan_entry = ttk.Entry(shodan_frame, width=60, show="*")
        self.shodan_entry.pack(fill='x', pady=2)
        self.shodan_entry.insert(0, self.shodan_api_key)
        
        # GitHub Token
        github_frame = ttk.Frame(api_frame)
        github_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(github_frame, text="GitHub Token:").pack(anchor='w')
        self.github_entry = ttk.Entry(github_frame, width=60, show="*")
        self.github_entry.pack(fill='x', pady=2)
        self.github_entry.insert(0, self.github_token)
        
        # Censys API
        censys_frame = ttk.Frame(api_frame)
        censys_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(censys_frame, text="Censys API ID:").pack(anchor='w')
        self.censys_id_entry = ttk.Entry(censys_frame, width=60)
        self.censys_id_entry.pack(fill='x', pady=2)
        self.censys_id_entry.insert(0, self.censys_api_id)
        
        ttk.Label(censys_frame, text="Censys Secret:").pack(anchor='w')
        self.censys_secret_entry = ttk.Entry(censys_frame, width=60, show="*")
        self.censys_secret_entry.pack(fill='x', pady=2)
        self.censys_secret_entry.insert(0, self.censys_secret)
        
        # VirusTotal API
        vt_frame = ttk.Frame(api_frame)
        vt_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(vt_frame, text="VirusTotal API Key:").pack(anchor='w')
        self.vt_entry = ttk.Entry(vt_frame, width=60, show="*")
        self.vt_entry.pack(fill='x', pady=2)
        self.vt_entry.insert(0, self.virustotal_api_key)
        
        # Scan Settings tab
        scan_frame = ttk.Frame(settings_notebook)
        settings_notebook.add(scan_frame, text="Scan Settings")
        
        ttk.Label(scan_frame, text="Scan Configuration", font=('Arial', 12, 'bold')).pack(pady=10)
        
         # Timeout setting
        timeout_frame = ttk.Frame(scan_frame)
        timeout_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(timeout_frame, text="Request Timeout (seconds):").pack(side='left')
        self.timeout_var = tk.StringVar(value=str(self.scan_settings.get('timeout', 10)))
        timeout_spin = ttk.Spinbox(timeout_frame, from_=1, to=60, width=10, textvariable=self.timeout_var)
        timeout_spin.pack(side='right')
        
        # Threads setting
        threads_frame = ttk.Frame(scan_frame)
        threads_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(threads_frame, text="Concurrent Threads:").pack(side='left')
        self.threads_var = tk.StringVar(value=str(self.scan_settings.get('threads', 5)))
        threads_spin = ttk.Spinbox(threads_frame, from_=1, to=20, width=10, textvariable=self.threads_var)
        threads_spin.pack(side='right')
        
        # Delay setting
        delay_frame = ttk.Frame(scan_frame)
        delay_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(delay_frame, text="Request Delay (seconds):").pack(side='left')
        self.delay_var = tk.StringVar(value=str(self.scan_settings.get('delay', 0.5)))
        delay_spin = ttk.Spinbox(delay_frame, from_=0, to=5, increment=0.1, width=10, textvariable=self.delay_var)
        delay_spin.pack(side='right')
        
        # User Agent setting
        ua_frame = ttk.Frame(scan_frame)
        ua_frame.pack(fill='x', padx=10, pady=5)
        ttk.Label(ua_frame, text="User Agent:").pack(anchor='w')
        self.ua_var = tk.StringVar(value=self.scan_settings.get('user_agent', 'WebSpy-Enhanced/2.0'))
        ua_entry = ttk.Entry(ua_frame, textvariable=self.ua_var, width=60)
        ua_entry.pack(fill='x', pady=2)
        
        # Buttons
        button_frame = ttk.Frame(settings_window)
        button_frame.pack(pady=10)
        
        def save_settings():
            # Save API keys
            self.shodan_api_key = self.shodan_entry.get()
            self.github_token = self.github_entry.get()
            self.censys_api_id = self.censys_id_entry.get()
            self.censys_secret = self.censys_secret_entry.get()
            self.virustotal_api_key = self.vt_entry.get()
            
            # Save scan settings
            self.scan_settings.update({
                'timeout': int(self.timeout_var.get()),
                'threads': int(self.threads_var.get()),
                'delay': float(self.delay_var.get()),
                'user_agent': self.ua_var.get()
            })
            
            self.save_configuration()
            settings_window.destroy()
            messagebox.showinfo("Success", "Settings saved successfully!")
        
        ttk.Button(button_frame, text="Save", command=save_settings).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side='left', padx=5)
    
    def show_reports_dialog(self):
        """Show reports and export dialog"""
        reports_window = tk.Toplevel(self.root)
        reports_window.title("Reports & Export")
        reports_window.geometry("500x400")
        reports_window.configure(bg='#2b2b2b')
        
        ttk.Label(reports_window, text="Reports & Export", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Export options
        export_frame = ttk.LabelFrame(reports_window, text="Export Options")
        export_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(export_frame, text="📋 Export All Results", command=self.export_all_results).pack(pady=5)
        ttk.Button(export_frame, text="📊 Generate HTML Report", command=self.generate_html_report).pack(pady=5)
        ttk.Button(export_frame, text="📄 Export to JSON", command=self.export_to_json).pack(pady=5)
        ttk.Button(export_frame, text="📈 Export to CSV", command=self.export_to_csv).pack(pady=5)
        
        # Logging options
        log_frame = ttk.LabelFrame(reports_window, text="Logging")
        log_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(log_frame, text="📝 View Logs", command=self.view_logs).pack(pady=5)
        ttk.Button(log_frame, text="🧹 Clear Logs", command=self.clear_logs).pack(pady=5)
        
        ttk.Button(reports_window, text="Close", command=reports_window.destroy).pack(pady=20)
    
    def show_tools_menu(self):
        """Show additional tools menu"""
        tools_window = tk.Toplevel(self.root)
        tools_window.title("Additional Tools")
        tools_window.geometry("400x300")
        tools_window.configure(bg='#2b2b2b')
        
        ttk.Label(tools_window, text="Additional Security Tools", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # External tools integration
        tools_frame = ttk.LabelFrame(tools_window, text="External Tools")
        tools_frame.pack(fill='x', padx=20, pady=10)
        
        # Only show tools that are available
        if self.available_tools['nmap']:
            ttk.Button(tools_frame, text="🔍 Launch Nmap", command=self.launch_nmap).pack(pady=2, fill='x')
        if self.available_tools['hydra']:
            ttk.Button(tools_frame, text="🔓 Launch Hydra", command=self.launch_hydra).pack(pady=2, fill='x')
        if self.available_tools['gobuster']:
            ttk.Button(tools_frame, text="🕷️ Launch Gobuster", command=self.launch_gobuster).pack(pady=2, fill='x')
        if self.available_tools['sqlmap']:
            ttk.Button(tools_frame, text="💉 Launch SQLMap", command=self.launch_sqlmap).pack(pady=2, fill='x')
        
        # Utility tools
        util_frame = ttk.LabelFrame(tools_window, text="Utilities")
        util_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(util_frame, text="🔢 Hash Calculator", command=self.hash_calculator).pack(pady=2, fill='x')
        ttk.Button(util_frame, text="🔓 Base64 Decoder", command=self.base64_tool).pack(pady=2, fill='x')
        ttk.Button(util_frame, text="🌐 URL Encoder", command=self.url_tool).pack(pady=2, fill='x')
        
        ttk.Button(tools_window, text="Close", command=tools_window.destroy).pack(pady=20)
    
    # Helper methods for thread-safe GUI updates
    def update_osint_text(self, text):
        """Thread-safe OSINT text update"""
        self.root.after(0, lambda: self.osint_text.insert(tk.END, text))
        self.root.after(0, lambda: self.osint_text.see(tk.END))  # Auto-scroll to end
    
    def update_vuln_text(self, text):
        """Thread-safe vulnerability text update"""
        self.root.after(0, lambda: self.vuln_text.insert(tk.END, text))
        self.root.after(0, lambda: self.vuln_text.see(tk.END))  # Auto-scroll to end
    
    def update_network_text(self, text):
        """Thread-safe network text update"""
        self.root.after(0, lambda: self.network_text.insert(tk.END, text))
        self.root.after(0, lambda: self.network_text.see(tk.END))  # Auto-scroll to end
    
    # Process results queue
    def process_results(self):
        """Process results from background threads"""
        try:
            while not self.results_queue.empty():
                result = self.results_queue.get_nowait()
                # Process result based on type
                if result['type'] == 'status':
                    self.status_label.config(text=result['message'])
                elif result['type'] == 'progress':
                    self.progress_detail.config(text=result['message'])
                # Add more result types as needed
                
        except queue.Empty:
            pass
        finally:
            self.root.after(1000, self.process_results)
    
    def stop_scan(self):
        """Stop all running scans"""
        self.stop_scanning.set()
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="Scan stopped by user")
        
        # Wait for threads to finish
        for thread in self.scan_threads:
            if thread.is_alive():
                thread.join(timeout=2)
        
        self.scan_threads.clear()
        self.stop_scanning.clear()
    
    # Safe request wrapper with error handling
    def safe_request(self, url, method='GET', **kwargs):
        """Safe wrapper for requests with error handling"""
        try:
            response = requests.request(method, url, timeout=self.scan_settings['timeout'], **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error for {url}: {e}")
            return None
    
    # Wrapper methods for existing functionality
    def osint_scan(self):
        """Quick OSINT scan"""
        self.shodan_lookup_wrapper()
        self.cert_transparency_lookup_wrapper()
        self.github_dork_search_wrapper()
    
    def shodan_lookup_wrapper(self):
        url = self.url_var.get().strip()
        if url:
            domain = urllib.parse.urlparse(url).netloc
            thread = threading.Thread(target=self.shodan_lookup, args=(domain,))
            thread.daemon = True
            thread.start()
    
    def cert_transparency_lookup_wrapper(self):
        url = self.url_var.get().strip()
        if url:
            domain = urllib.parse.urlparse(url).netloc
            thread = threading.Thread(target=self.cert_transparency_lookup, args=(domain,))
            thread.daemon = True
            thread.start()
    
    def github_dork_search_wrapper(self):
        thread = threading.Thread(target=self.github_dork_search)
        thread.daemon = True
        thread.start()
    
    def test_sql_injection_wrapper(self):
        thread = threading.Thread(target=self.test_sql_injection)
        thread.daemon = True
        thread.start()
    
    def check_robots_wrapper(self):
        url = self.url_var.get().strip()
        if url:
            base_url = '/'.join(url.split('/')[:3])
            thread = threading.Thread(target=self.check_robots_txt, args=(base_url,))
            thread.daemon = True
            thread.start()
    
    def analyze_security_headers_wrapper(self):
        url = self.url_var.get().strip()
        if url:
            thread = threading.Thread(target=self.analyze_security_headers, args=(url,))
            thread.daemon = True
            thread.start()
    
    def analyze_ssl_tls_wrapper(self):
        url = self.url_var.get().strip()
        if url:
            domain = urllib.parse.urlparse(url).netloc
            thread = threading.Thread(target=self.analyze_ssl_tls, args=(domain,))
            thread.daemon = True
            thread.start()
    
    # Placeholder methods for new functionality - implement as needed
    def load_custom_wordlist(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filename:
            try:
                with open(filename, 'r') as f:
                    wordlist = [line.strip() for line in f.readlines() if line.strip()]
                self.custom_wordlists[os.path.basename(filename)] = wordlist
                self.wordlist_var.set("custom")
                messagebox.showinfo("Info", f"Custom wordlist loaded: {filename} ({len(wordlist)} entries)")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
    
    def find_sitemaps(self):
        """Find sitemaps for the target domain"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        base_url = '/'.join(url.split('/')[:3])
        thread = threading.Thread(target=self._find_sitemaps_impl, args=(base_url,))
        thread.daemon = True
        thread.start()
    
    def _find_sitemaps_impl(self, base_url):
        """Sitemap discovery implementation"""
        try:
            result = "🗺️ SITEMAP DISCOVERY\n" + "="*40 + "\n\n"
            result += f"Target: {base_url}\n\n"
            
            # Common sitemap locations
            sitemap_locations = [
                "/sitemap.xml",
                "/sitemap_index.xml",
                "/sitemap/index.xml",
                "/sitemap.php",
                "/sitemap.txt",
                "/sitemap.xml.gz",
                "/sitemap/sitemap.xml",
                "/wp-sitemap.xml",
                "/robots.txt"  # Check robots.txt for sitemap reference
            ]
            
            found_sitemaps = []
            
            # First check robots.txt for sitemap reference
            robots_url = f"{base_url}/robots.txt"
            response = self.safe_request(robots_url)
            
            if response and response.status_code == 200:
                for line in response.text.split('\n'):
                    if line.lower().startswith('sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        found_sitemaps.append(("Robots.txt reference", sitemap_url))
                        result += f"✅ Found in robots.txt: {sitemap_url}\n"
            
            # Check common sitemap locations
            for location in sitemap_locations:
                sitemap_url = f"{base_url}{location}"
                response = self.safe_request(sitemap_url)
                
                if response and response.status_code == 200:
                    found_sitemaps.append(("Direct access", sitemap_url))
                    result += f"✅ Found: {sitemap_url}\n"
            
            if not found_sitemaps:
                result += "❌ No sitemaps found\n"
                result += "💡 Try common CMS-specific sitemap locations\n"
            
            self.root.after(0, lambda: self.robots_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Sitemap discovery error: {str(e)}\n"
            self.root.after(0, lambda: self.robots_text.insert(tk.END, error_msg))
    
    def check_security_txt(self):
        """Check for security.txt file"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        base_url = '/'.join(url.split('/')[:3])
        thread = threading.Thread(target=self._check_security_txt_impl, args=(base_url,))
        thread.daemon = True
        thread.start()
    
    def _check_security_txt_impl(self, base_url):
        """Security.txt check implementation"""
        try:
            security_urls = [
                f"{base_url}/.well-known/security.txt",
                f"{base_url}/security.txt"
            ]
            
            result = "📄 SECURITY.TXT CHECK\n" + "="*40 + "\n\n"
            
            for url in security_urls:
                try:
                    response = self.safe_request(url)
                    if response and response.status_code == 200:
                        result += f"✅ Found: {url}\n\n"
                        result += response.text
                        result += "\n" + "="*40 + "\n"
                        break
                except:
                    continue
            else:
                result += "❌ No security.txt file found\n"
                result += "💡 Consider implementing RFC 9116 security.txt\n"
            
            self.root.after(0, lambda: self.robots_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Security.txt check error: {str(e)}\n"
            self.root.after(0, lambda: self.robots_text.insert(tk.END, error_msg))
    
    def owasp_header_check(self):
        """Check headers against OWASP recommendations"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._owasp_header_check_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _owasp_header_check_impl(self, url):
        """OWASP header check implementation"""
        try:
            response = self.safe_request(url)
            if not response:
                self.root.after(0, lambda: self.security_text.insert(tk.END, "❌ Failed to fetch URL\n"))
                return
                
            headers = response.headers
            
            result = "📊 OWASP SECURITY HEADERS CHECK\n" + "="*40 + "\n\n"
            
            owasp_headers = {
                'Strict-Transport-Security': {
                    'required': True,
                    'description': 'Force HTTPS connections',
                    'recommendation': 'max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'required': True,
                    'description': 'Prevent XSS and injection attacks',
                    'recommendation': "default-src 'self'"
                },
                'X-Content-Type-Options': {
                    'required': True,
                    'description': 'Prevent MIME-type sniffing',
                    'recommendation': 'nosniff'
                },
                'X-Frame-Options': {
                    'required': True,
                    'description': 'Prevent clickjacking',
                    'recommendation': 'DENY or SAMEORIGIN'
                },
                'Referrer-Policy': {
                    'required': False,
                    'description': 'Control referrer information',
                    'recommendation': 'strict-origin-when-cross-origin'
                }
            }
            
            score = 0
            max_score = sum(1 if h['required'] else 0.5 for h in owasp_headers.values())
            
            for header, config in owasp_headers.items():
                header_value = headers.get(header, '')
                
                if header_value:
                    score += 1 if config['required'] else 0.5
                    result += f"✅ {header}: {header_value[:50]}...\n"
                else:
                    result += f"❌ Missing: {header}\n"
                    result += f"   Purpose: {config['description']}\n"
                    result += f"   Recommendation: {config['recommendation']}\n\n"
            
            percentage = (score / max_score) * 100
            result += f"\n📊 OWASP COMPLIANCE SCORE: {percentage:.1f}%\n"
            
            if percentage >= 90:
                result += "🟢 Excellent security posture\n"
            elif percentage >= 70:
                result += "🟡 Good but needs improvement\n"
            else:
                result += "🔴 Poor security headers implementation\n"
            
            self.root.after(0, lambda: self.security_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ OWASP check error: {str(e)}\n"
            self.root.after(0, lambda: self.security_text.insert(tk.END, error_msg))
    
    def calculate_security_score(self):
        """Calculate overall security score"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._calculate_security_score_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _calculate_security_score_impl(self, url):
        """Security score calculation implementation"""
        try:
            result = "⚡ SECURITY SCORE CALCULATION\n" + "="*40 + "\n\n"
            
            response = self.safe_request(url)
            if not response:
                self.root.after(0, lambda: self.security_text.insert(tk.END, "❌ Failed to fetch URL\n"))
                return
                
            headers = response.headers
            
            score_components = {}
            
            # Security headers (40 points)
            security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 
                              'X-Frame-Options', 'X-Content-Type-Options']
            headers_present = sum(1 for h in security_headers if h in headers)
            headers_score = (headers_present / len(security_headers)) * 40
            score_components['Security Headers'] = headers_score
            
            # HTTPS usage (20 points)
            https_score = 20 if url.startswith('https://') else 0
            score_components['HTTPS Usage'] = https_score
            
            # Server information disclosure (10 points)
            server_header = headers.get('Server', '')
            server_score = 0 if server_header and any(x in server_header.lower() 
                                                    for x in ['apache/', 'nginx/', 'iis/']) else 10
            score_components['Server Security'] = server_score
            
            # Cookie security (15 points)
            cookies = response.cookies
            secure_cookies = sum(1 for c in cookies if c.secure)
            cookie_score = (secure_cookies / max(len(cookies), 1)) * 15 if cookies else 15
            score_components['Cookie Security'] = cookie_score
            
            # Content type (15 points)
            content_type = headers.get('Content-Type', '').lower()
            content_score = 15 if 'text/html' in content_type and 'charset' in content_type else 10
            score_components['Content Security'] = content_score
            
            total_score = sum(score_components.values())
            
            result += "📊 SECURITY SCORE BREAKDOWN:\n"
            for component, score in score_components.items():
                result += f"   {component}: {score:.1f}/40\n" if component == "Security Headers" else f"   {component}: {score:.1f}\n"
            
            result += f"\n🎯 TOTAL SECURITY SCORE: {total_score:.1f}/100\n\n"
            
            if total_score >= 80:
                result += "🟢 EXCELLENT - Strong security implementation\n"
            elif total_score >= 60:
                result += "🟡 GOOD - Some security measures in place\n"
            elif total_score >= 40:
                result += "🟠 FAIR - Basic security, needs improvement\n"
            else:
                result += "🔴 POOR - Significant security issues\n"
            
            self.root.after(0, lambda: self.security_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Security score error: {str(e)}\n"
            self.root.after(0, lambda: self.security_text.insert(tk.END, error_msg))
    
    def ssl_labs_check(self):
        """SSL Labs API check"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        thread = threading.Thread(target=self._ssl_labs_check_impl, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _ssl_labs_check_impl(self, domain):
        """SSL Labs check implementation"""
        try:
            result = "🏆 SSL LABS ANALYSIS\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            # Start SSL Labs scan
            api_url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&startNew=on"
            
            result += "🔍 Initiating SSL Labs scan...\n"
            result += "⏳ This may take several minutes\n\n"
            
            response = self.safe_request(api_url)
            
            if response and response.status_code == 200:
                data = response.json()
                status = data.get('status', 'UNKNOWN')
                
                result += f"Scan Status: {status}\n"
                
                if status in ['READY', 'ERROR']:
                    endpoints = data.get('endpoints', [])
                    for endpoint in endpoints:
                        grade = endpoint.get('grade', 'Unknown')
                        ip = endpoint.get('ipAddress', 'Unknown')
                        result += f"IP: {ip} - Grade: {grade}\n"
                else:
                    result += "💡 Visit SSL Labs manually for detailed results:\n"
                    result += f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}\n"
            else:
                result += f"❌ SSL Labs API error: {response.status_code if response else 'No response'}\n"
                result += "💡 Check SSL Labs manually for results\n"
            
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ SSL Labs check error: {str(e)}\n"
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, error_msg))
    
    def cipher_analysis(self):
        """Analyze SSL/TLS cipher suites"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        domain = urllib.parse.urlparse(url).netloc
        thread = threading.Thread(target=self._cipher_analysis_impl, args=(domain,))
        thread.daemon = True
        thread.start()
    
    def _cipher_analysis_impl(self, domain):
        """Cipher analysis implementation"""
        try:
            result = "🔐 CIPHER SUITE ANALYSIS\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    result += f"TLS Version: {version}\n"
                    result += f"Cipher Suite: {cipher[0]}\n"
                    result += f"Key Exchange: {cipher[1]}\n"
                    result += f"Authentication: {cipher[2] if len(cipher) > 2 else 'Unknown'}\n\n"
                    
                    # Analyze cipher strength
                    cipher_name = cipher[0].upper()
                    
                    if 'AES256' in cipher_name or 'CHACHA20' in cipher_name:
                        result += "🟢 Strong encryption (256-bit)\n"
                    elif 'AES128' in cipher_name:
                        result += "🟡 Good encryption (128-bit)\n"
                    elif 'RC4' in cipher_name or 'DES' in cipher_name:
                        result += "🔴 Weak encryption - VULNERABLE\n"
                    
                    # Check for forward secrecy
                    if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                        result += "✅ Perfect Forward Secrecy supported\n"
                    else:
                        result += "❌ No Perfect Forward Secrecy\n"
                    
                    # TLS version assessment
                    if version in ['TLSv1.3']:
                        result += "🟢 Excellent TLS version\n"
                    elif version in ['TLSv1.2']:
                        result += "🟡 Good TLS version\n"
                    elif version in ['TLSv1.1', 'TLSv1.0']:
                        result += "🟠 Outdated TLS version\n"
                    else:
                        result += "🔴 Deprecated TLS version\n"
            
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Cipher analysis error: {str(e)}\n"
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, error_msg))
    
    # Report generation methods
    def save_report(self):
        """Save comprehensive scan report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"webspy_report_{timestamp}.txt"
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialname=filename
            )
            
            if filename:
                report_content = self.generate_text_report()
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report_content)
                
                messagebox.showinfo("Success", f"Report saved to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {str(e)}")
    
    def generate_text_report(self):
        """Generate comprehensive text report"""
        report = f"""
WebSpy Enhanced Security Testing Report
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {self.url_var.get()}
Platform: {platform.system()} {platform.release()}
Python: {platform.python_version()}

OVERVIEW
{'-'*60}
{self.overview_text.get(1.0, tk.END)}

DIRECTORY FUZZING RESULTS
{'-'*60}
{self.fuzz_text.get(1.0, tk.END)}

OSINT RESULTS
{'-'*60}
{self.osint_text.get(1.0, tk.END)}

VULNERABILITY ASSESSMENT
{'-'*60}
{self.vuln_text.get(1.0, tk.END)}

NETWORK ANALYSIS
{'-'*60}
{self.network_text.get(1.0, tk.END)}

SECURITY HEADERS
{'-'*60}
{self.security_text.get(1.0, tk.END)}

SSL/TLS ANALYSIS
{'-'*60}
{self.ssl_text.get(1.0, tk.END)}

ROBOTS.TXT & SITEMAPS
{'-'*60}
{self.robots_text.get(1.0, tk.END)}

{'='*60}
Report End
"""
        return report
    
    def export_all_results(self):
        """Export all results to text file"""
        self.save_report()
    
    def generate_html_report(self):
        """Generate HTML report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"webspy_report_{timestamp}.html"
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
                initialname=filename
            )
            
            if filename:
                html_content = self.generate_html_content()
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                messagebox.showinfo("Success", f"HTML report saved to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate HTML report: {str(e)}")
    
    def generate_html_content(self):
        """Generate HTML report content"""
        target_url = self.url_var.get()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>WebSpy Enhanced Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #2b2b2b; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }}
        pre {{ background: #1e1e1e; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .timestamp {{ color: #666; font-style: italic; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WebSpy Enhanced Security Testing Report</h1>
        <p>Target: {target_url}</p>
        <p class="timestamp">Generated: {timestamp}</p>
        <p class="timestamp">Platform: {platform.system()} {platform.release()}</p>
    </div>
    
    <div class="section">
        <h2>Overview</h2>
        <pre>{self.overview_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>Directory Fuzzing</h2>
        <pre>{self.fuzz_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>OSINT Results</h2>
        <pre>{self.osint_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>Vulnerability Assessment</h2>
        <pre>{self.vuln_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>Network Analysis</h2>
        <pre>{self.network_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>Security Headers</h2>
        <pre>{self.security_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>SSL/TLS Analysis</h2>
        <pre>{self.ssl_text.get(1.0, tk.END)}</pre>
    </div>
    
    <div class="section">
        <h2>Robots.txt & Sitemaps</h2>
        <pre>{self.robots_text.get(1.0, tk.END)}</pre>
    </div>
    
</body>
</html>
"""
        return html
    
    def export_to_json(self):
        """Export results to JSON format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"webspy_results_{timestamp}.json"
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialname=filename
            )
            
            if filename:
                json_data = {
                    "scan_info": {
                        "target": self.url_var.get(),
                        "timestamp": datetime.now().isoformat(),
                        "tool": "WebSpy Enhanced v2.0",
                        "platform": f"{platform.system()} {platform.release()}"
                    },
                    "results": {
                        "overview": self.overview_text.get(1.0, tk.END),
                        "directory_fuzzing": self.fuzz_text.get(1.0, tk.END),
                        "osint": self.osint_text.get(1.0, tk.END),
                        "vulnerabilities": self.vuln_text.get(1.0, tk.END),
                        "network": self.network_text.get(1.0, tk.END),
                        "security_headers": self.security_text.get(1.0, tk.END),
                        "ssl_tls": self.ssl_text.get(1.0, tk.END),
                        "robots": self.robots_text.get(1.0, tk.END)
                    }
                }
                
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(json_data, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Success", f"JSON export saved to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export JSON: {str(e)}")
    
    def export_to_csv(self):
        """Export results to CSV format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"webspy_results_{timestamp}.csv"
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialname=filename
            )
            
            if filename:
                # Create a simple CSV with basic information
                import csv
                
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["WebSpy Enhanced Security Report"])
                    writer.writerow(["Generated", datetime.now().isoformat()])
                    writer.writerow(["Target", self.url_var.get()])
                    writer.writerow(["Platform", f"{platform.system()} {platform.release()}"])
                    writer.writerow([])
                    writer.writerow(["Section", "Summary"])
                    
                    # Add basic summaries for each section
                    sections = [
                        ("Overview", self.overview_text.get(1.0, tk.END)),
                        ("Directory Fuzzing", self.fuzz_text.get(1.0, tk.END)),
                        ("OSINT", self.osint_text.get(1.0, tk.END)),
                        ("Vulnerabilities", self.vuln_text.get(1.0, tk.END)),
                        ("Network", self.network_text.get(1.0, tk.END)),
                        ("Security Headers", self.security_text.get(1.0, tk.END)),
                        ("SSL/TLS", self.ssl_text.get(1.0, tk.END)),
                        ("Robots.txt", self.robots_text.get(1.0, tk.END))
                    ]
                    
                    for section_name, content in sections:
                        # Create a simple summary
                        lines = content.split('\n')
                        summary = f"{len(lines)} lines of data"
                        writer.writerow([section_name, summary])
                
                messagebox.showinfo("Success", f"CSV export saved to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")
    
    def view_logs(self):
        """View application logs"""
        log_dir = os.path.expanduser("~/.webspy_logs")
        if os.path.exists(log_dir):
            if platform.system() == "Windows":
                os.startfile(log_dir)
            else:
                subprocess.run(["xdg-open", log_dir])
        else:
            messagebox.showinfo("Info", "No log directory found")
    
    def clear_logs(self):
        """Clear application logs"""
        if messagebox.askyesno("Confirm", "Clear all application logs?"):
            log_dir = os.path.expanduser("~/.webspy_logs")
            try:
                for file in os.listdir(log_dir):
                    os.remove(os.path.join(log_dir, file))
                messagebox.showinfo("Success", "Logs cleared")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
    
    # External tool integration methods
    def launch_nmap(self):
        """Launch Nmap GUI if available"""
        if self.available_tools['nmap']:
            try:
                if self.is_windows:
                    subprocess.Popen(["nmap", "-T4", "-A", "-v"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(["x-terminal-emulator", "-e", "nmap -T4 -A -v"])
                messagebox.showinfo("Info", "Nmap launched in new window")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to launch Nmap: {str(e)}")
        else:
            messagebox.showinfo("Info", "Nmap is not available on this system")
    
    def launch_hydra(self):
        """Launch Hydra GUI if available"""
        if self.available_tools['hydra']:
            try:
                if self.is_windows:
                    subprocess.Popen(["hydra"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(["x-terminal-emulator", "-e", "hydra"])
                messagebox.showinfo("Info", "Hydra launched in new window")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to launch Hydra: {str(e)}")
        else:
            messagebox.showinfo("Info", "Hydra is not available on this system")
    
    def launch_gobuster(self):
        """Launch Gobuster GUI if available"""
        if self.available_tools['gobuster']:
            try:
                if self.is_windows:
                    subprocess.Popen(["gobuster"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(["x-terminal-emulator", "-e", "gobuster"])
                messagebox.showinfo("Info", "Gobuster launched in new window")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to launch Gobuster: {str(e)}")
        else:
            messagebox.showinfo("Info", "Gobuster is not available on this system")
    
    def launch_sqlmap(self):
        """Launch SQLMap GUI if available"""
        if self.available_tools['sqlmap']:
            try:
                if self.is_windows:
                    subprocess.Popen(["sqlmap", "-h"], creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(["x-terminal-emulator", "-e", "sqlmap -h"])
                messagebox.showinfo("Info", "SQLMap launched in new window")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to launch SQLMap: {str(e)}")
        else:
            messagebox.showinfo("Info", "SQLMap is not available on this system")
    
    # Utility tools
    def hash_calculator(self):
        """Hash calculator utility"""
        hash_window = tk.Toplevel(self.root)
        hash_window.title("Hash Calculator")
        hash_window.geometry("500x400")
        hash_window.configure(bg='#2b2b2b')
        
        ttk.Label(hash_window, text="Hash Calculator", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Input
        ttk.Label(hash_window, text="Input:").pack(anchor='w', padx=20)
        input_text = scrolledtext.ScrolledText(hash_window, height=5, bg='#1e1e1e', fg='white')
        input_text.pack(fill='x', padx=20, pady=5)
        
        # Hash type selection
        hash_frame = ttk.Frame(hash_window)
        hash_frame.pack(fill='x', padx=20, pady=5)
        
        hash_var = tk.StringVar(value="md5")
        ttk.Radiobutton(hash_frame, text="MD5", variable=hash_var, value="md5").pack(side='left')
        ttk.Radiobutton(hash_frame, text="SHA1", variable=hash_var, value="sha1").pack(side='left')
        ttk.Radiobutton(hash_frame, text="SHA256", variable=hash_var, value="sha256").pack(side='left')
        ttk.Radiobutton(hash_frame, text="SHA512", variable=hash_var, value="sha512").pack(side='left')
        
        # Output
        ttk.Label(hash_window, text="Hash:").pack(anchor='w', padx=20, pady=(10,0))
        output_text = scrolledtext.ScrolledText(hash_window, height=3, bg='#1e1e1e', fg='white')
        output_text.pack(fill='x', padx=20, pady=5)
        
        def calculate_hash():
            try:
                input_data = input_text.get(1.0, tk.END).strip().encode('utf-8')
                hash_type = hash_var.get()
                
                if hash_type == "md5":
                    result = hashlib.md5(input_data).hexdigest()
                elif hash_type == "sha1":
                    result = hashlib.sha1(input_data).hexdigest()
                elif hash_type == "sha256":
                    result = hashlib.sha256(input_data).hexdigest()
                elif hash_type == "sha512":
                    result = hashlib.sha512(input_data).hexdigest()
                
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, result)
                
            except Exception as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {str(e)}")
        
        ttk.Button(hash_window, text="Calculate", command=calculate_hash).pack(pady=10)
    
    def base64_tool(self):
        """Base64 encoder/decoder utility"""
        b64_window = tk.Toplevel(self.root)
        b64_window.title("Base64 Tool")
        b64_window.geometry("500x400")
        b64_window.configure(bg='#2b2b2b')
        
        ttk.Label(b64_window, text="Base64 Encoder/Decoder", font=('Arial', 14, 'bold')).pack(pady=10)
        
        # Input
        ttk.Label(b64_window, text="Input:").pack(anchor='w', padx=20)
        input_text = scrolledtext.ScrolledText(b64_window, height=5, bg='#1e1e1e', fg='white')
        input_text.pack(fill='x', padx=20, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(b64_window)
        button_frame.pack(pady=10)
        
        # Output
        ttk.Label(b64_window, text="Output:").pack(anchor='w', padx=20)
        output_text = scrolledtext.ScrolledText(b64_window, height=5, bg='#1e1e1e', fg='white')
        output_text.pack(fill='x', padx=20, pady=5)
        
        def encode_b64():
            try:
                input_data = input_text.get(1.0, tk.END).strip()
                result = base64.b64encode(input_data.encode('utf-8')).decode('utf-8')
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, result)
            except Exception as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {str(e)}")
        
        def decode_b64():
            try:
                input_data = input_text.get(1.0, tk.END).strip()
                result = base64.b64decode(input_data).decode('utf-8')
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, result)
            except Exception as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {str(e)}")
        
        ttk.Button(button_frame, text="Encode", command=encode_b64).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decode", command=decode_b64).pack(side='left', padx=5)
    
    def url_tool(self):
        """URL encoder/decoder utility"""
        url_window = tk.Toplevel(self.root)
        url_window.title("URL Tool")
        url_window.geometry("500x400")
        url_window.configure(bg='#2b2b2b')
        
        # Input
        ttk.Label(url_window, text="Input:").pack(anchor='w', padx=20)
        input_text = scrolledtext.ScrolledText(url_window, height=5, bg='#1e1e1e', fg='white')
        input_text.pack(fill='x', padx=20, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(url_window)
        button_frame.pack(pady=10)
        
        # Output
        ttk.Label(url_window, text="Output:").pack(anchor='w', padx=20)
        output_text = scrolledtext.ScrolledText(url_window, height=5, bg='#1e1e1e', fg='white')
        output_text.pack(fill='x', padx=20, pady=5)
        
        def encode_url():
            try:
                input_data = input_text.get(1.0, tk.END).strip()
                result = urllib.parse.quote(input_data, safe='')
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, result)
            except Exception as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {str(e)}")
        
        def decode_url():
            try:
                input_data = input_text.get(1.0, tk.END).strip()
                result = urllib.parse.unquote(input_data)
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, result)
            except Exception as e:
                output_text.delete(1.0, tk.END)
                output_text.insert(1.0, f"Error: {str(e)}")
        
        ttk.Button(button_frame, text="Encode", command=encode_url).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decode", command=decode_url).pack(side='left', padx=5)

    def refresh_overview(self):
        """Refresh overview information"""
        url = self.url_var.get().strip()
        if url:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            self.update_overview(url, domain, "Overview Refresh")

    def add_system_info(self):
        """Add system information"""
        try:
            if self.is_raspberry_pi:
                with open('/proc/device-tree/model', 'r') as f:
                    self.pi_model = f.read().strip()
            else:
                self.pi_model = f"{platform.system()} {platform.release()}"
                
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
                self.cpu_count = cpuinfo.count('processor')
        except:
            self.pi_model = f"{platform.system()} {platform.release()}"
            self.cpu_count = os.cpu_count() or 4

    def monitor_pi_performance(self):
        """Monitor Pi temperature and performance"""
        try:
            if self.is_raspberry_pi and os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp = int(f.read()) / 1000.0
                
                temp_color = 'white'
                if temp > 70:
                    temp_color = 'red'
                elif temp > 60:
                    temp_color = 'orange'
                elif temp > 50:
                    temp_color = 'yellow'
                
                self.temp_label.config(text=f"Temperature: {temp:.1f}°C", foreground=temp_color)
            
            # Update performance stats
            if hasattr(self, 'scan_start_time') and self.scan_start_time:
                elapsed = time.time() - self.scan_start_time
                self.performance_label.config(text=f"URLs tested: {self.urls_tested} | Time: {elapsed:.0f}s")
            
        except:
            if hasattr(self, 'temp_label'):
                self.temp_label.config(text="Temperature: N/A")
            
        self.root.after(5000, self.monitor_pi_performance)

    def monitor_system_performance(self):
        """Monitor system performance for non-Pi systems"""
        try:
            # Update performance stats
            if hasattr(self, 'scan_start_time') and self.scan_start_time:
                elapsed = time.time() - self.scan_start_time
                self.performance_label.config(text=f"URLs tested: {self.urls_tested} | Time: {elapsed:.0f}s")
            
        except Exception as e:
            self.logger.error(f"Performance monitoring error: {e}")
            
        self.root.after(5000, self.monitor_system_performance)

    def show_system_info(self):
        """Show system information"""
        try:
            if self.is_windows:
                cpu_info = platform.processor()
                memory_info = subprocess.check_output(['wmic', 'OS', 'get', 'TotalVisibleMemorySize', '/Value']).decode().split('=')[1].strip()
                memory_info = f"{int(memory_info) / 1024 / 1024:.1f} GB"
            else:
                cpu_info = subprocess.check_output(['lscpu']).decode()
                memory_info = subprocess.check_output(['free', '-h']).decode()
            
            info_text = f"""
System Information
{'='*40}
Platform: {platform.system()} {platform.release()}
Python: {platform.python_version()}
CPU: {self.cpu_count} cores
Architecture: {platform.machine()}

WebSpy Enhanced v2.0
Cross-platform security testing suite
"""
            messagebox.showinfo("System Info", info_text)
        except Exception as e:
            messagebox.showerror("Error", f"Could not get system info: {e}")

    def start_scan(self):
        """Start comprehensive security scan"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_var.set(url)
        
        self.clear_all_tabs()
        self.progress.start()
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_label.config(text="Full Security Scan in Progress...")
        self.scan_start_time = time.time()
        self.urls_tested = 0
        
        scan_thread = threading.Thread(target=self.perform_full_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
        self.scan_threads.append(scan_thread)

    def quick_scan(self):
        """Perform quick security assessment"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_var.set(url)
        
        self.progress.start()
        self.status_label.config(text="Quick Scan...")
        
        scan_thread = threading.Thread(target=self.perform_quick_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()

    def perform_full_scan(self, url):
        """Perform comprehensive security scan"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            base_url = f"{parsed_url.scheme}://{domain}"
            
            self.logger.info(f"Starting full scan of {url}")
            
            # Update overview
            self.update_overview(url, domain, "Full Security Scan")
            
            if self.stop_scanning.is_set():
                return
            
            # Run all scanning modules with progress updates
            scan_tasks = [
                (self.check_robots_txt, base_url, "Checking robots.txt"),
                (self.analyze_security_headers, url, "Analyzing security headers"),
                (self.analyze_ssl_tls, domain, "Analyzing SSL/TLS"),
                (self.start_directory_fuzzing, None, "Directory fuzzing"),
                (self.shodan_lookup, domain, "Shodan lookup"),
                (self.cert_transparency_lookup, domain, "Certificate transparency"),
                (self.github_dork_search, None, "GitHub dorking"),
                (self.pastebin_search, domain, "Pastebin monitoring"),
                (self.linkfinder_scan, url, "LinkFinder scan"),
            ]
            
            # Only add Nikto if available
            if self.available_tools['nikto']:
                scan_tasks.append((self.start_nikto_scan, None, "Nikto scan"))
                
            scan_tasks.append((self.test_sql_injection, None, "SQL injection test"))
            
            for i, (task_func, param, description) in enumerate(scan_tasks):
                if self.stop_scanning.is_set():
                    break
                    
                self.root.after(0, lambda desc=description: 
                    self.progress_detail.config(text=f"Step {i+1}/{len(scan_tasks)}: {desc}"))
                
                try:
                    if param:
                        task_func(param)
                    else:
                        task_func()
                except Exception as e:
                    self.logger.error(f"Error in {description}: {e}")
                    continue
                
                time.sleep(1)  # Brief pause between tasks
            
        except Exception as e:
            self.logger.error(f"Error during full scan: {e}")
            self.root.after(0, lambda: self.overview_text.insert(tk.END, f"Error during scan: {str(e)}\n"))
        finally:
            self.root.after(0, self.scan_complete)

    def perform_quick_scan(self, url):
        """Perform quick security assessment"""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            
            self.logger.info(f"Starting quick scan of {url}")
            
            self.update_overview(url, domain, "Quick Security Assessment")
            self.check_robots_txt(url.replace(parsed_url.path, ''))
            self.analyze_security_headers(url)
            self.quick_vuln_check()
            
        except Exception as e:
            self.logger.error(f"Error during quick scan: {e}")
            self.root.after(0, lambda: self.overview_text.insert(tk.END, f"Error during quick scan: {str(e)}\n"))
        finally:
            self.root.after(0, self.scan_complete)

    def start_directory_fuzzing(self):
        """Start directory fuzzing (FFuF/Gobuster equivalent)"""
        url = self.url_var.get().strip()
        if not url:
            return
            
        fuzz_thread = threading.Thread(target=self.directory_fuzzing, args=(url,))
        fuzz_thread.daemon = True
        fuzz_thread.start()

    def directory_fuzzing(self, url):
        """Perform directory fuzzing with threading"""
        try:
            wordlist_type = self.wordlist_var.get()
            max_threads = int(self.fuzz_threads_var.get())
            
            # Enhanced wordlists
            wordlists = {
                "common": [
                    "admin", "administrator", "login", "test", "backup", "old", "new",
                    "api", "v1", "v2", "docs", "documentation", "help", "support",
                    "dev", "development", "staging", "prod", "production", "www",
                    "config", "database", "db", "sql", "files", "uploads", "images"
                ],
                "medium": [
                    "admin", "administrator", "login", "panel", "dashboard", "control",
                    "test", "testing", "backup", "backups", "old", "new", "temp", "tmp",
                    "api", "v1", "v2", "v3", "docs", "documentation", "help", "support",
                    "dev", "development", "staging", "stage", "prod", "production",
                    "www", "ftp", "mail", "email", "blog", "news", "shop", "store",
                    "upload", "uploads", "download", "downloads", "files", "images",
                    "assets", "static", "css", "js", "img", "media", "content",
                    "config", "configuration", "database", "db", "sql", "mysql",
                    "phpmyadmin", "wp-admin", "wp-content", "wp-includes",
                    "manage", "manager", "console", "cpanel", "webmail"
                ],
                "large": [
                    # Include all from medium plus additional entries
                    "admin", "administrator", "login", "signin", "signup", "register",
                    "panel", "dashboard", "control", "manage", "manager", "console",
                    "test", "testing", "demo", "example", "sample", "backup", "backups",
                    "old", "new", "temp", "tmp", "cache", "log", "logs", "archive",
                    "api", "v1", "v2", "v3", "v4", "rest", "graphql", "docs", "documentation",
                    "help", "support", "faq", "about", "contact", "info", "privacy",
                    "terms", "legal", "policy", "dev", "development", "staging", "stage",
                    "prod", "production", "live", "www", "ftp", "sftp", "mail", "email",
                    "webmail", "blog", "news", "shop", "store", "ecommerce", "cart",
                    "checkout", "payment", "pay", "invoice", "billing", "account",
                    "profile", "user", "users", "member", "members", "client", "clients",
                    "upload", "uploads", "download", "downloads", "files", "file",
                    "images", "img", "image", "photo", "photos", "video", "videos",
                    "audio", "music", "assets", "static", "css", "js", "javascript",
                    "styles", "scripts", "media", "content", "data", "export", "import"
                ]
            }
            
            # Use custom wordlist if selected
            if wordlist_type == "custom" and self.custom_wordlists:
                selected_wordlist = list(self.custom_wordlists.values())[0]
            else:
                selected_wordlist = wordlists.get(wordlist_type, wordlists["common"])
            
            result = "Directory Fuzzing Results\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n"
            result += f"Wordlist: {wordlist_type} ({len(selected_wordlist)} entries)\n"
            result += f"Threads: {max_threads}\n\n"
            
            self.root.after(0, lambda: self.fuzz_text.insert(tk.END, result))
            
            found_directories = []
            
            # Use ThreadPoolExecutor for concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_dir = {
                    executor.submit(self.test_directory, url, directory): directory 
                    for directory in selected_wordlist
                }
                
                for future in concurrent.futures.as_completed(future_to_dir):
                    if self.stop_scanning.is_set():
                        break
                        
                    directory = future_to_dir[future]
                    try:
                        result_data = future.result()
                        if result_data:
                            status_code, directory_name = result_data
                            status_emoji = {200: "✅", 301: "↪️", 302: "↪️", 403: "🔒", 401: "🔐"}
                            emoji = status_emoji.get(status_code, "❓")
                            
                            result_line = f"{emoji} /{directory_name} ({status_code})\n"
                            self.root.after(0, lambda line=result_line: self.fuzz_text.insert(tk.END, line))
                            found_directories.append((directory_name, status_code))
                            
                    except Exception as e:
                        self.logger.error(f"Error testing directory {directory}: {e}")
            
            summary = f"\nFuzzing Complete\nFound {len(found_directories)} interesting directories\n"
            self.root.after(0, lambda: self.fuzz_text.insert(tk.END, summary))
            
        except Exception as e:
            error_msg = f"Directory fuzzing error: {str(e)}\n"
            self.root.after(0, lambda: self.fuzz_text.insert(tk.END, error_msg))

    def test_directory(self, base_url, directory):
        """Test a single directory"""
        try:
            test_url = base_url.rstrip('/') + '/' + directory
            response = requests.head(
                test_url, 
                timeout=self.scan_settings['timeout'], 
                allow_redirects=False,
                headers={'User-Agent': self.scan_settings['user_agent']}
            )
            
            self.urls_tested += 1
            
            if response.status_code in [200, 301, 302, 403, 401]:
                return (response.status_code, directory)
                
            time.sleep(self.scan_settings['delay'])
            
        except Exception as e:
            self.logger.debug(f"Error testing directory {directory}: {e}")
            return None

    def clear_all_tabs(self):
        """Clear all tab contents"""
        for widget_name in ['overview_text', 'fuzz_text', 'osint_text', 'vuln_text',
                           'network_text', 'robots_text', 'security_text', 'ssl_text']:
            widget = getattr(self, widget_name, None)
            if widget:
                widget.delete(1.0, tk.END)

    def scan_complete(self):
        """Called when scan is complete"""
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="Scan Complete")
        self.progress_detail.config(text="")
        
        if hasattr(self, 'scan_start_time') and self.scan_start_time:
            elapsed = time.time() - self.scan_start_time
            self.logger.info(f"Scan completed in {elapsed:.1f} seconds, {self.urls_tested} URLs tested")

    def update_overview(self, url, domain, scan_type="Full Security Scan"):
        """Update the overview tab with basic info"""
        platform_icon = "🍓" if self.is_raspberry_pi else "🖥️" if self.is_windows else "🐧" if self.is_linux else "🍎"
        platform_name = "Raspberry Pi" if self.is_raspberry_pi else "Windows" if self.is_windows else "Linux" if self.is_linux else "macOS"
        
        overview_info = f"""
WebSpy Enhanced v2.0 - Security Testing Suite
{'='*60}
Target URL: {url}
Domain: {domain}
Scan Type: {scan_type}
Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Platform: {platform_name} {platform_icon}
CPU Cores: {getattr(self, 'cpu_count', 'Unknown')}

Enhanced Security Tools Available:
✓ Advanced Directory Fuzzing with threading
✓ Multi-source OSINT (Shodan, Censys, VirusTotal)
✓ Certificate Transparency Logs
✓ GitHub Dorking for Leaked Credentials
✓ Comprehensive Vulnerability Testing (XSS, LFI, CRLF, SQLi)
✓ Network Analysis (Port Scan, Traceroute, Whois, Geolocation)
✓ Advanced Security Headers Analysis (OWASP compliance)
✓ SSL/TLS Deep Analysis with cipher assessment
✓ Enhanced Reporting (HTML, JSON, CSV export)
✓ External Tool Integration
✓ Built-in Utility Tools

Scan Progress:
Initializing comprehensive security assessment...
Check individual tabs for detailed results!

Ethical Use Notice:
This tool is for authorized security testing only.
Ensure you have permission before testing any target.
Respect rate limits and terms of service.

Optimized for {platform_name} with enhanced performance monitoring
"""
        self.root.after(0, lambda: self.overview_text.insert(tk.END, overview_info))

    # Implement the missing methods that were referenced
    def shodan_lookup(self, domain):
        """Shodan API lookup - enhanced version"""
        if not self.shodan_api_key:
            self.update_osint_text("❌ Shodan API key not configured. Please add it in Settings.\n")
            return
        
        try:
            # Get IP address of domain
            import socket
            ip = socket.gethostbyname(domain)
            
            # Shodan API request
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
            response = self.safe_request(url)
            
            if response and response.status_code == 200:
                data = response.json()
                result = f"🔍 SHODAN LOOKUP - {domain}\n{'='*40}\n\n"
                result += f"IP: {data.get('ip_str', 'Unknown')}\n"
                result += f"Organization: {data.get('org', 'Unknown')}\n"
                result += f"Operating System: {data.get('os', 'Unknown')}\n"
                result += f"Ports: {', '.join(map(str, data.get('ports', [])))}\n\n"
                
                if 'vulns' in data and data['vulns']:
                    result += "🚨 VULNERABILITIES:\n"
                    for vuln in data['vulns']:
                        result += f"  • {vuln}\n"
                
                self.update_osint_text(result)
            else:
                error_msg = f"❌ Shodan API error: {response.status_code if response else 'No response'}\n"
                self.update_osint_text(error_msg)
                
        except socket.gaierror:
            self.update_osint_text(f"❌ Could not resolve domain: {domain}\n")
        except Exception as e:
            self.update_osint_text(f"❌ Shodan lookup error: {str(e)}\n")
    
    def cert_transparency_lookup(self, domain):
        """Certificate Transparency lookup implementation"""
        try:
            # Use crt.sh for certificate transparency lookup
            url = f"https://crt.sh/?q={domain}&output=json"
            response = self.safe_request(url)
            
            if response and response.status_code == 200:
                certificates = response.json()
                result = f"📋 CERTIFICATE TRANSPARENCY - {domain}\n{'='*40}\n\n"
                
                if certificates:
                    result += f"Found {len(certificates)} certificates\n\n"
                    for cert in certificates[:5]:  # Show first 5
                        result += f"Name: {cert.get('name_value', 'Unknown')}\n"
                        result += f"Issuer: {cert.get('issuer_name', 'Unknown')}\n"
                        result += f"Valid from: {cert.get('not_before', 'Unknown')}\n"
                        result += f"Valid to: {cert.get('not_after', 'Unknown')}\n"
                        result += "-" * 20 + "\n"
                else:
                    result += "No certificates found in transparency logs\n"
                    
                self.update_osint_text(result)
            else:
                error_msg = f"❌ Certificate transparency lookup error: {response.status_code if response else 'No response'}\n"
                self.update_osint_text(error_msg)
                
        except Exception as e:
            self.update_osint_text(f"❌ Certificate transparency error: {str(e)}\n")
    
    def github_dork_search(self):
        """GitHub dorking - enhanced version"""
        if not self.github_token:
            self.update_osint_text("❌ GitHub token not configured. Please add it in Settings.\n")
            return
        
        try:
            domain = urllib.parse.urlparse(self.url_var.get()).netloc
            result = f"🐙 GITHUB DORK SEARCH - {domain}\n{'='*40}\n\n"
            
            # Common GitHub dorks for the domain
            dorks = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
                f'"{domain}" token',
                f'"{domain}" config',
                f'"{domain}" env',
            ]
            
            result += "Common GitHub dorks for this domain:\n"
            for dork in dorks:
                result += f"  • {dork}\n"
            
            result += "\n💡 Search these manually at: https://github.com/search\n"
            result += "🔐 GitHub API access requires proper authentication\n"
            
            self.update_osint_text(result)
            
        except Exception as e:
            self.update_osint_text(f"❌ GitHub dork search error: {str(e)}\n")
    
    def pastebin_search(self, domain):
        """Pastebin search - enhanced version"""
        try:
            result = f"📋 PASTEBIN MONITORING - {domain}\n{'='*40}\n\n"
            result += "Pastebin monitoring requires external services or manual checking.\n\n"
            result += "💡 Check these pastebin monitoring services:\n"
            result += "  • https://psbdmp.ws/ - Pastebin dump search\n"
            result += "  • https://www.google.com/search?q=site:pastebin.com+\"{domain}\"\n"
            result += "  • https://www.google.com/search?q=site:pastebin.com+\"{domain}\"+password\n"
            
            self.update_osint_text(result)
            
        except Exception as e:
            self.update_osint_text(f"❌ Pastebin search error: {str(e)}\n")
    
    def linkfinder_scan(self, url):
        """LinkFinder scan - enhanced version"""
        try:
            result = f"🔗 LINKFINDER SCAN - {url}\n{'='*40}\n\n"
            result += "LinkFinder is a Python script that extracts endpoints from JavaScript files.\n\n"
            result += "💡 To use LinkFinder:\n"
            result += "  1. Install it: pip install linkfinder\n"
            result += "  2. Run: python -m linkfinder -i {url} -o cli\n"
            result += "  3. Or download JS files and analyze them manually\n"
            
            self.update_osint_text(result)
            
        except Exception as e:
            self.update_osint_text(f"❌ LinkFinder scan error: {str(e)}\n")
    
    def start_nikto_scan(self):
        """Nikto scan - enhanced version"""
        if not self.available_tools['nikto']:
            self.update_vuln_text("❌ Nikto is not available on this system\n")
            return
        
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._nikto_scan_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _nikto_scan_impl(self, url):
        """Nikto scan implementation"""
        try:
            result = "🛡️ NIKTO SCAN\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            # Run nikto scan
            cmd = ["nikto", "-h", url, "-Tuning", "x", "-o", "-"]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            
            if stdout:
                result += stdout
            if stderr:
                result += f"\nErrors:\n{stderr}"
            
            self.update_vuln_text(result)
            
        except subprocess.TimeoutExpired:
            error_msg = "❌ Nikto scan timeout\n"
            self.update_vuln_text(error_msg)
        except Exception as e:
            error_msg = f"❌ Nikto scan error: {str(e)}\n"
            self.update_vuln_text(error_msg)
    
    def test_sql_injection(self):
        """SQL injection test - enhanced version"""
        url = self.url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        
        thread = threading.Thread(target=self._test_sql_injection_impl, args=(url,))
        thread.daemon = True
        thread.start()
    
    def _test_sql_injection_impl(self, url):
        """SQL injection testing implementation"""
        try:
            result = "💉 SQL INJECTION TEST\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            # SQL injection payloads
            payloads = [
                "'",
                "''",
                "`",
                "\"",
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "UNION SELECT NULL--",
                "OR 1=1",
                "admin'--"
            ]
            
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                result += "❌ No parameters found for SQL injection testing\n"
                result += "💡 SQL injection testing requires URLs with parameters\n"
                self.update_vuln_text(result)
                return
            
            vulnerabilities = []
            
            for param_name in params.keys():
                result += f"\n🎯 Testing parameter: {param_name}\n"
                
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                        
                        response = self.safe_request(test_url)
                        
                        if response:
                            # Check for common SQL error messages
                            error_indicators = [
                                "sql", "mysql", "ora-", "syntax", "database", "query failed",
                                "you have an error in your sql syntax",
                                "warning: mysql", "unclosed quotation mark"
                            ]
                            
                            for indicator in error_indicators:
                                if indicator in response.text.lower():
                                    vuln_info = f"Potential SQLi in {param_name} with payload: {payload}"
                                    vulnerabilities.append(vuln_info)
                                    result += f"🚨 POTENTIAL SQLi: {payload[:30]}...\n"
                                    break
                                    
                    except Exception as e:
                        continue
            
            result += f"\n📊 SQL INJECTION TEST SUMMARY:\n"
            result += f"Parameters tested: {len(params)}\n"
            result += f"Potential vulnerabilities: {len(vulnerabilities)}\n"
            
            if vulnerabilities:
                result += "\n🚨 POTENTIAL SQL INJECTION VULNERABILITIES:\n"
                for vuln in vulnerabilities:
                    result += f"   • {vuln}\n"
            else:
                result += "\n✅ No obvious SQL injection vulnerabilities found\n"
            
            self.update_vuln_text(result)
            
        except Exception as e:
            error_msg = f"❌ SQL injection testing error: {str(e)}\n"
            self.update_vuln_text(error_msg)
    
    def check_robots_txt(self, base_url):
        """Check robots.txt - enhanced version"""
        try:
            result = "🤖 ROBOTS.TXT ANALYSIS\n" + "="*40 + "\n\n"
            result += f"Target: {base_url}/robots.txt\n\n"
            
            robots_url = f"{base_url}/robots.txt"
            response = self.safe_request(robots_url)
            
            if response and response.status_code == 200:
                result += "✅ Found robots.txt file\n\n"
                result += response.text
                result += "\n" + "="*40 + "\n"
                
                # Parse robots.txt
                rp = RobotFileParser()
                rp.parse(response.text.splitlines())
                
                # Check for sitemap reference
                if rp.site_maps():
                    result += f"\n📋 Sitemap references found:\n"
                    for sitemap in rp.site_maps():
                        result += f"  • {sitemap}\n"
                
            else:
                result += "❌ No robots.txt file found or inaccessible\n"
            
            self.root.after(0, lambda: self.robots_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Robots.txt check error: {str(e)}\n"
            self.root.after(0, lambda: self.robots_text.insert(tk.END, error_msg))
    
    def analyze_security_headers(self, url):
        """Security headers analysis - enhanced version"""
        try:
            result = "🛡️ SECURITY HEADERS ANALYSIS\n" + "="*40 + "\n\n"
            result += f"Target: {url}\n\n"
            
            response = self.safe_request(url)
            if not response:
                result += "❌ Failed to fetch URL\n"
                self.root.after(0, lambda: self.security_text.insert(tk.END, result))
                return
                
            headers = response.headers
            
            # Check for important security headers
            security_headers = {
                'Strict-Transport-Security': 'Forces HTTPS connections',
                'Content-Security-Policy': 'Prevents XSS and other code injection attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-XSS-Protection': 'Enables XSS protection in older browsers',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features and APIs',
                'Feature-Policy': 'Controls browser features and APIs (older)'
            }
            
            found_headers = 0
            total_headers = len(security_headers)
            
            for header, description in security_headers.items():
                if header in headers:
                    found_headers += 1
                    result += f"✅ {header}: {headers[header]}\n"
                    result += f"   Purpose: {description}\n\n"
                else:
                    result += f"❌ Missing: {header}\n"
                    result += f"   Purpose: {description}\n\n"
            
            # Calculate security score
            security_score = (found_headers / total_headers) * 100
            result += f"📊 SECURITY HEADERS SCORE: {security_score:.1f}%\n"
            
            if security_score >= 80:
                result += "🟢 Excellent security headers implementation\n"
            elif security_score >= 60:
                result += "🟡 Good security headers, room for improvement\n"
            else:
                result += "🔴 Poor security headers implementation\n"
            
            self.root.after(0, lambda: self.security_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Security headers analysis error: {str(e)}\n"
            self.root.after(0, lambda: self.security_text.insert(tk.END, error_msg))
    
    def analyze_ssl_tls(self, domain):
        """SSL/TLS analysis - enhanced version"""
        try:
            result = "🔐 SSL/TLS ANALYSIS\n" + "="*40 + "\n\n"
            result += f"Target: {domain}\n\n"
            
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    result += f"TLS Version: {version}\n"
                    result += f"Cipher Suite: {cipher[0]}\n"
                    result += f"Key Exchange: {cipher[1]}\n"
                    result += f"Authentication: {cipher[2] if len(cipher) > 2 else 'Unknown'}\n\n"
                    
                    # Certificate information
                    result += "📜 CERTIFICATE INFORMATION:\n"
                    if cert:
                        result += f"Subject: {cert.get('subject', 'Unknown')}\n"
                        result += f"Issuer: {cert.get('issuer', 'Unknown')}\n"
                        
                        # Validity period
                        not_before = cert.get('notBefore', 'Unknown')
                        not_after = cert.get('notAfter', 'Unknown')
                        result += f"Valid from: {not_before}\n"
                        result += f"Valid until: {not_after}\n"
                        
                        # Check if certificate is expired
                        if not_after != 'Unknown':
                            from datetime import datetime
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            if expiry_date < datetime.now():
                                result += "🔴 CERTIFICATE EXPIRED!\n"
                            else:
                                result += "✅ Certificate is valid\n"
                    
                    # Analyze cipher strength
                    cipher_name = cipher[0].upper()
                    
                    if 'AES256' in cipher_name or 'CHACHA20' in cipher_name:
                        result += "🟢 Strong encryption (256-bit)\n"
                    elif 'AES128' in cipher_name:
                        result += "🟡 Good encryption (128-bit)\n"
                    elif 'RC4' in cipher_name or 'DES' in cipher_name:
                        result += "🔴 Weak encryption - VULNERABLE\n"
                    
                    # Check for forward secrecy
                    if 'ECDHE' in cipher_name or 'DHE' in cipher_name:
                        result += "✅ Perfect Forward Secrecy supported\n"
                    else:
                        result += "❌ No Perfect Forward Secrecy\n"
                    
                    # TLS version assessment
                    if version in ['TLSv1.3']:
                        result += "🟢 Excellent TLS version\n"
                    elif version in ['TLSv1.2']:
                        result += "🟡 Good TLS version\n"
                    elif version in ['TLSv1.1', 'TLSv1.0']:
                        result += "🟠 Outdated TLS version\n"
                    else:
                        result += "🔴 Deprecated TLS version\n"
            
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ SSL/TLS analysis error: {str(e)}\n"
            self.root.after(0, lambda: self.ssl_text.insert(tk.END, error_msg))
    
    def quick_vuln_check(self):
        """Quick vulnerability check"""
        try:
            result = "⚡ QUICK VULNERABILITY CHECK\n" + "="*40 + "\n\n"
            result += "This is a basic vulnerability assessment.\n"
            result += "For comprehensive testing, use the dedicated tools in each tab.\n\n"
            
            result += "🔍 Check the following tabs for detailed analysis:\n"
            result += "  • Vulnerabilities - XSS, SQLi, LFI, CRLF tests\n"
            result += "  • Security Headers - OWASP compliance check\n"
            result += "  • SSL/TLS - Certificate and encryption analysis\n"
            result += "  • Network - Port scanning and network analysis\n"
            result += "  • OSINT - External intelligence gathering\n"
            
            self.root.after(0, lambda: self.overview_text.insert(tk.END, result))
            
        except Exception as e:
            error_msg = f"❌ Quick vulnerability check error: {str(e)}\n"
            self.root.after(0, lambda: self.overview_text.insert(tk.END, error_msg))
    
    def directory_fuzz(self):
        """Quick directory fuzzing"""
        self.start_directory_fuzzing()
    
    def ssl_quick_check(self):
        """Quick SSL check"""
        url = self.url_var.get().strip()
        if url:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            self.analyze_ssl_tls(domain)
    
    def nikto_scan(self):
        """Quick Nikto scan"""
        self.start_nikto_scan()

def main():
    root = tk.Tk()
    app = WebSpyEnhanced(root)
    
    # Enhanced welcome message
    platform_icon = "🍓" if app.is_raspberry_pi else "🖥️" if app.is_windows else "🐧" if app.is_linux else "🍎"
    platform_name = "Raspberry Pi" if app.is_raspberry_pi else "Windows" if app.is_windows else "Linux" if app.is_linux else "macOS"
    
    app.overview_text.insert(tk.END, f"""
Welcome to WebSpy Enhanced v2.0 - Advanced Security Testing Suite!

System Information:
Running on: {platform_name} {platform_icon}
CPU Cores: {getattr(app, 'cpu_count', 'Unknown')}
Python Version: {platform.python_version()}

New Features in v2.0:
• Enhanced multi-threaded directory fuzzing
• Comprehensive OSINT integration (Shodan, Censys, VirusTotal)
• Advanced vulnerability testing (XSS, LFI, CRLF injection, SQLi)
• Network analysis tools (Port scanning, Traceroute, Whois, Geolocation)
• OWASP-compliant security headers assessment
• Advanced SSL/TLS cipher analysis
• Professional reporting (HTML, JSON, CSV export)
• Built-in utility tools (Hash calculator, Base64, URL encoder)
• Configuration management and logging
• External tool integration framework
• Cross-platform support (Windows, Linux, macOS, Raspberry Pi)

Getting Started:
1. Enter your target URL in the field above
2. Configure API keys in Settings for enhanced OSINT capabilities
3. Choose your scan type:
   • Full Scan - Comprehensive security assessment
   • Quick Scan - Basic vulnerability check
   • Individual tools for targeted testing

Enhanced Performance Features:
• Platform-specific optimizations
• Configurable threading and timeouts
• Request rate limiting to respect targets
• Comprehensive logging system
• Scan progress tracking

Security Testing Categories:
• Information Gathering (OSINT, DNS, SSL/TLS)
• Vulnerability Assessment (XSS, SQLi, LFI, CRLF)
• Network Analysis (Port scanning, Traceroute)
• Configuration Assessment (Headers, Robots.txt)
• Reporting and Documentation

Ethical Use Policy:
This tool is designed for authorized security testing only.
• Obtain proper written authorization before testing
• Respect website terms of service and rate limits
• Follow responsible disclosure practices
• Use only on systems you own or have explicit permission to test
• Comply with local laws and regulations

Performance Optimization:
• Close unnecessary applications for best performance
• Use wired network connection when possible
• Adjust thread count based on system performance

Ready to begin advanced security testing!
Configure your settings and start scanning.
""")
    
    root.mainloop()

if __name__ == "__main__":
    main()

