import os
import time
import json
import random
import threading
import asyncio
from collections import deque
from io import StringIO
import csv

# Flask modules
from flask import Flask, Response, jsonify, request
from flask import render_template_string, redirect, url_for

# ---------------------------------------------------------------------
# --- Global State Management ---
# ---------------------------------------------------------------------

class DataStore:
    """Manages all global application state, counters, and logs."""
    def __init__(self):
        self.session_start = time.time()
        self.total_packets = 0
        self.attack_counts = {
            "Normal": 0, "DoS": 0, "BruteForce": 0, 
            "Bot": 0, "PortScan": 0, "Infiltration": 0
        }
        # Max 100 packets for the live feed table
        self.live_packets = deque(maxlen=100)
        # Full historical log for the Alerts Manager
        self.historical_alerts = []
        self.top_ips = {}
        self.session_running = threading.Event() # Controls capture thread
        self.session_running.set() # Start running by default

        self.LOCK = threading.Lock()
        
    def add_log(self, log_entry):
        """Adds a new log entry, updates counts, and updates the live feed."""
        with self.LOCK:
            
            self.total_packets += 1
            attack_type = log_entry['attack']
            self.attack_counts[attack_type] = self.attack_counts.get(attack_type, 0) + 1
            
            # Add action metadata and severity
            log_entry['action'] = 'Block' if attack_type != 'Normal' else '-'
            log_entry['severity'] = self.get_severity(attack_type)
            log_entry['id'] = len(self.historical_alerts) + 1 # Simple unique ID

            self.live_packets.appendleft(log_entry) # Add to the front for live feed
            self.historical_alerts.append(log_entry) # Add to the end for historical log

            # Update Top IPs
            src_ip = log_entry['src_ip']
            self.top_ips[src_ip] = self.top_ips.get(src_ip, 0) + 1

    def get_severity(self, attack):
        """Helper to assign severity based on attack type."""
        if attack in ['DoS', 'Bot', 'Infiltration']:
            return 'High'
        elif attack in ['BruteForce', 'PortScan']:
            return 'Warning'
        else:
            return 'Normal'

    def get_metrics(self):
        """Returns summarized metrics for the dashboard cards."""
        with self.LOCK:
            attack_types = [k for k, v in self.attack_counts.items() if k != 'Normal' and v > 0]
            
            # Get the highest severity from *all* attacks recorded so far
            all_attacks = [k for k, v in self.attack_counts.items() if v > 0]
            highest_severity = max(
                (self.get_severity(k) for k in all_attacks),
                key=lambda x: {'High': 3, 'Warning': 2, 'Normal': 1}.get(x, 0),
                default='Normal'
            )
            
            total_attacks = sum(v for k, v in self.attack_counts.items() if k != 'Normal')
            
            if self.total_packets == 0:
                normal_percent = 0
            else:
                normal_percent = (self.attack_counts.get('Normal', 0) / self.total_packets) * 100

            uptime = int(time.time() - self.session_start)
            
            return {
                "total_packets": self.total_packets,
                "total_attacks": total_attacks,
                "highest_severity": highest_severity,
                "normal_percent": f"{normal_percent:.1f}%",
                "uptime": uptime,
                "attack_distribution": list(self.attack_counts.items()),
                "top_ips": sorted(self.top_ips.items(), key=lambda item: item[1], reverse=True)[:10],
                "live_packets": list(self.live_packets)
            }

    def reset_counters(self):
        """Resets all session-specific counters."""
        with self.LOCK:
            self.session_start = time.time()
            self.total_packets = 0
            self.attack_counts = {k: 0 for k in self.attack_counts}
            self.live_packets.clear()
            self.historical_alerts.clear()
            self.top_ips.clear()

# Initialize the global data store
data_store = DataStore()

# New: Mode Management
MODE_SIMULATION = 'Demo (Simulated Traffic)'
MODE_LIVE = 'Live (Conceptual Network Capture)'
current_mode = MODE_SIMULATION # Start in demo mode

# --- NIDS Data Simulation/Capture Threads ---
def start_demo_capture(data_store):
    """Synthetic traffic generator for Demo Mode."""
    # Weights slightly adjusted for smoother visualization
    attacks = ["Normal", "DoS", "BruteForce", "Bot", "PortScan", "Infiltration", "Normal"]
    weights = [0.70, 0.10, 0.07, 0.05, 0.05, 0.03, 0.00] 
    
    while data_store.session_running.is_set():
        try:
            # Generate more diverse IPs to make the top IPs chart interesting
            ip_base = random.choice(["192.168.1.", "10.0.0.", "172.16.0."])
            src = f"{ip_base}{random.randint(10, 250)}"
            dst = f"10.0.0.{random.randint(10, 250)}"
            attack = random.choices(attacks, weights=weights, k=1)[0]
            
            log = {
                "time": time.strftime("%H:%M:%S"),
                "src_ip": src,
                "dst_ip": dst,
                "attack": attack
            }
            data_store.add_log(log)
            time.sleep(random.uniform(0.5, 1.2)) # Variable delay
        except Exception:
            time.sleep(5)
            
def start_live_capture(data_store):
    # Simulate high-speed, varied traffic that might be seen on a real network
    real_ips = ["192.168.1.100", "192.168.1.1", "10.0.0.5", "172.16.0.2", "8.8.8.8", "1.1.1.1"]
    attacks = ["Normal", "Normal", "Normal", "DoS", "PortScan", "BruteForce"]
    weights = [0.75, 0.08, 0.07, 0.05, 0.03, 0.02] 
    
    while data_store.session_running.is_set():
        try:
            # Generate faster, varied logs
            src = random.choice(real_ips)
            dst = random.choice(real_ips)
            while src == dst:
                dst = random.choice(real_ips)
                
            attack = random.choices(attacks, weights=weights, k=1)[0]
            
            log = {
                "time": time.strftime("%H:%M:%S"),
                "src_ip": src,
                "dst_ip": dst,
                "attack": attack
            }
            data_store.add_log(log)
            # Faster polling rate for "live" feel
            time.sleep(random.uniform(0.1, 0.5)) 
        except Exception:
            time.sleep(5)

# Start the background data thread immediately in the default mode
capture_thread = threading.Thread(target=start_demo_capture, args=(data_store,), daemon=True)
capture_thread.start()

# --- LLM Integration for Report Generation ---
# NOTE: This function remains the same as it correctly handles report generation.
async def generate_nids_report(metrics_summary, top_ips_summary):
    """
    Generates a detailed NIDS summary report using the Gemini API (MOCK response).
    """
    system_prompt = (
        "Act as a cybersecurity expert and network analyst. "
        "Analyze the provided NIDS metrics and generate a concise, professional, "
        "three-paragraph executive summary. "
        "Paragraph 1: Summarize the overall session health (total traffic, attack count, highest threat). "
        "Paragraph 2: Detail the top 3 most frequent attacks and explain what causes them and their typical impact. "
        "Paragraph 3: Recommend immediate and strategic actions based on the report. "
        "Format the output using Markdown (e.g., **bold** for key terms)."
    )

    user_query = f"""
    Generate a NIDS Security Report based on the following real-time data:
    - Total Packets: {metrics_summary.get('total_packets', 0)}
    - Total Attacks Detected: {metrics_summary.get('total_attacks', 0)}
    - Normal Traffic Percentage: {metrics_summary.get('normal_percent', '0.0%')}
    - Highest Severity Detected: {metrics_summary.get('highest_severity', 'Normal')}
    - Attack Distribution: {dict(metrics_summary.get('attack_distribution', []))}
    - Top 3 Threat Source IPs: {top_ips_summary}
    """
    
    # Placeholder for API Key (will be filled by the Canvas runtime)
    api_key = "" 
    model_name = "gemini-2.5-flash-preview-05-20"
    api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"

    # Build the payload
    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "tools": [{"google_search": {} }], # Enable Google Search for grounding
        "systemInstruction": {"parts": [{"text": system_prompt}]},
    }

    report_content = "Report generation failed or returned no content."
    
    # Simple retry mechanism for fetch
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # --- START MOCK API CALL ---
            total_packets = metrics_summary.get('total_packets', 0)

            if total_packets < 5:
                 return (
                    "**Initial Analysis Required**\n\n"
                    "The system requires more data to generate a meaningful security report. "
                    f"Currently, only {total_packets} packets have been processed. "
                    "Please wait for the live feed to run for a few minutes."
                 )

            # Determine top attack for dynamic content
            attack_dist = dict(metrics_summary.get('attack_distribution', []))
            top_attack_name = max(
                (k for k, v in attack_dist.items() if k != 'Normal'), 
                key=lambda k: attack_dist[k], 
                default='None'
            )
            
            top_ip_display = ""
            if top_ips_summary:
                top_ip_display = f"The top attacking IP, `{top_ips_summary[0]['ip']}` with `{top_ips_summary[0]['count']} attempts`, is a key indicator of a concentrated threat vector."
            else:
                top_ip_display = "No specific source IPs are currently flagged as primary threats."


            # Removed leading newline to fix spacing issue
            mock_response_text = f"""
## Executive Security Report: Session Summary ({current_mode})

The current session, running in **{current_mode}**, has processed a total of **{total_packets}** packets, of which **{metrics_summary['total_attacks']}** were classified as malicious activity. 
Normal traffic accounts for **{metrics_summary['normal_percent']}** of the total. The security posture is currently rated with a **{metrics_summary['highest_severity']}** 
threat level due to consistent detection of **{top_attack_name}** activity.

The most frequent malicious activity observed is **{top_attack_name}**. 
This attack type aims to disrupt network operations or gain unauthorized access. Common attacks like **DoS** (Denial of Service) 
overload resources, while **PortScan** activities precede targeted exploits. {top_ip_display}

Immediate action should focus on reviewing and permanently blocking any **Top Threat Source IPs** identified. 
Strategically, it is recommended to implement **tighter ingress filtering** and **rate limiting** to mitigate DoS and BruteForce attempts effectively. 
A regular review of firewall rules and network policies is essential to maintain a robust security environment.
"""
            
            return mock_response_text.strip() # Ensure no leading/trailing whitespace
            # --- END MOCK API CALL ---
        
        except Exception:
            time.sleep(2 ** attempt) # Exponential backoff
            if attempt == max_retries - 1:
                return "Report generation service is currently unavailable. Please check the network connection or API service status."
            continue
    
    return report_content

# --- HTML TEMPLATES (Combined) ---
# Base HTML Structure (The <head>, sidebar, and main layout)
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Security Dashboard - {{ title }}</title>
    <!-- Load Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Configure Tailwind to use Inter font and smooth colors -->
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        'primary-blue': '#3b82f6',
                        'success-green': '#10b981',
                        'warning-orange': '#f59e0b',
                        'high-red': '#ef4444',
                        'normal-grey': '#9ca3af',
                    }
                }
            }
        }
    </script>
    <!-- Include Chart.js (for graphs) -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
    <!-- Removed streaming plugin as trend chart is gone. -->
    <style>
        /* Custom scrollbar for better aesthetic */
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #f1f1f1; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }
        
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }

        /* Styling for the Report Page (to make it look printable) */
        .report-content {
            white-space: pre-wrap; /* Preserve formatting from Markdown/LLM output */
            line-height: 1.6;
            padding: 2rem;
            border-radius: 0.75rem;
            background-color: white;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }

        /* Simple Markdown to HTML styling (for the mock) */
        .report-content strong { font-weight: 700; color: #3b82f6; } /* Primary Blue for strong */
        .report-content code { background-color: #f3f4f6; padding: 2px 4px; border-radius: 4px; font-weight: 600; }
        .report-content p { margin-bottom: 1rem; }
        
        /* FIX: Ensure markdown headings are rendered correctly */
        .report-content h2 { font-size: 1.75rem; font-weight: 700; margin-top: 2rem; margin-bottom: 1rem; }
        .report-content h3 { font-size: 1.5rem; font-weight: 600; margin-top: 1.5rem; margin-bottom: 0.5rem; }
        
        /* Remove the margin/padding for the very first element in the report container */
        .report-content > :first-child { margin-top: 0 !important; padding-top: 0 !important; }


        /* Media query for print styling (PDF download) */
        @media print {
            body {
                margin: 0;
                padding: 0;
            }
            .sidebar, header, .no-print {
                display: none !important;
            }
            main {
                padding: 0 !important;
            }
            .report-content {
                box-shadow: none !important;
                border: none !important;
            }
        }
    </style>
</head>

<body class="bg-gray-50 font-sans antialiased text-gray-800">

    <div class="flex h-screen overflow-hidden">
        
        <!-- Sidebar Navigation -->
        <div class="flex flex-col w-64 bg-white border-r border-gray-200 sidebar">
            <div class="p-6 flex items-center justify-center border-b border-gray-200">
                <span class="text-2xl font-extrabold text-primary-blue">NIDS</span>
                <span class="text-2xl font-light text-gray-500 ml-1">Dashboard</span>
            </div>
            
            <nav class="flex-grow p-4 space-y-2">
                <a href="{{ url_for('index') }}" class="flex items-center p-3 rounded-xl {% if title == 'Dashboard' %}bg-primary-blue text-white shadow-md{% else %}text-gray-600 hover:bg-gray-100{% endif %} transition duration-150 ease-in-out">
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                    <span>Dashboard</span>
                </a>
                
                <a href="{{ url_for('alerts') }}" class="flex items-center p-3 rounded-xl {% if title == 'Alerts Manager' %}bg-primary-blue text-white shadow-md{% else %}text-gray-600 hover:bg-gray-100{% endif %} transition duration-150 ease-in-out">
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1"></path></svg>
                    <span>Alerts Manager</span>
                </a>

                <!-- New Report Link -->
                <a href="{{ url_for('report') }}" class="flex items-center p-3 rounded-xl {% if title == 'Security Report' %}bg-primary-blue text-white shadow-md{% else %}text-gray-600 hover:bg-gray-100{% endif %} transition duration-150 ease-in-out">
                    <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V17a2 2 0 01-2 2z"></path></svg>
                    <span>Report</span>
                </a>

            </nav>
        </div>
        
        <!-- Main Content Area -->
        <div class="flex flex-col flex-1 overflow-y-auto">
            
            <!-- Header/Top Bar -->
            <header class="bg-white border-b border-gray-200 p-4 shadow-sm flex justify-between items-center">
                <h1 class="text-xl font-semibold text-gray-700">{{ title }}</h1>
                <div class="flex items-center space-x-4">
                    <span class="text-sm text-gray-500">Admin</span>
                    <div class="w-8 h-8 bg-gray-300 rounded-full"></div>
                </div>
            </header>
            
            <!-- Content Block -->
            <main class="p-6">
                {{ content }}
            </main>
        </div>
        
        <!-- Modal for IP Block Confirmation (Replaces alert()) -->
        <div id="ipBlockModal" class="hidden fixed inset-0 bg-gray-900 bg-opacity-50 flex items-center justify-center z-50">
            <div class="bg-white p-6 rounded-xl shadow-2xl w-full max-w-sm">
                <h3 class="text-lg font-semibold text-high-red mb-4">⚠️ Confirm IP Block</h3>
                <p class="text-gray-600 mb-6">Are you sure you want to permanently block the IP address: <strong id="ipToBlockDisplay" class="text-gray-900"></strong>?</p>
                <div class="flex justify-end space-x-3">
                    <button onclick="closeBlockModal()" class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition">Cancel</button>
                    <button id="confirmBlockBtn" class="px-4 py-2 text-sm font-medium text-white bg-high-red hover:bg-red-600 rounded-lg transition">Block IP Permanently</button>
                </div>
            </div>
        </div>
        
    </div>

    <script>
        let currentIpToBlock = '';

        function openBlockModal(ip) {
            currentIpToBlock = ip;
            document.getElementById('ipToBlockDisplay').textContent = ip;
            document.getElementById('ipBlockModal').classList.remove('hidden');
        }

        function closeBlockModal() {
            document.getElementById('ipBlockModal').classList.add('hidden');
            currentIpToBlock = '';
        }

        document.getElementById('confirmBlockBtn').addEventListener('click', async () => {
            if (currentIpToBlock) {
                // Perform the actual AJAX call to the Flask route
                const response = await fetch(`/block_ip/${currentIpToBlock}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const result = await response.json();
                
                console.log(result.message); 
                
                // Disable the block button on the live feed table if available
                const buttons = document.querySelectorAll('button[data-ip="' + currentIpToBlock + '"]');
                buttons.forEach(btn => {
                    btn.textContent = 'BLOCKED';
                    btn.classList.remove('bg-high-red', 'hover:bg-red-600');
                    btn.classList.add('bg-gray-400', 'cursor-not-allowed');
                    btn.disabled = true;
                });

                closeBlockModal();
            }
        });

    </script>

</body>
</html>
"""

# Dashboard Content (Tabs, Cards, Table, Charts)
DASHBOARD_CONTENT = """
<!-- Tab Navigation -->
<div class="border-b border-gray-200">
    <nav class="-mb-px flex space-x-8" aria-label="Tabs">
        <a href="#" onclick="switchTab('liveFeed')" class="tab-link active-tab border-primary-blue text-primary-blue whitespace-nowrap py-3 px-1 border-b-2 font-medium text-sm transition duration-150 ease-in-out">
            🟢 Live Feed
        </a>
        <a href="#" onclick="switchTab('attackGraphs')" class="tab-link border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 whitespace-nowrap py-3 px-1 border-b-2 font-medium text-sm transition duration-150 ease-in-out">
            🔵 Attack Graphs
        </a>
    </nav>
</div>

<!-- LIVE FEED TAB CONTENT -->
<div id="liveFeed" class="tab-content active mt-6 space-y-6">
    
    <!-- Controls and Metrics Bar -->
    <div class="bg-white p-4 rounded-xl shadow-lg flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0 md:space-x-4">
        
        <!-- Mode Display and Toggle -->
        <div class="text-sm font-medium text-gray-600 border border-gray-200 p-2 rounded-lg w-full md:w-auto text-center md:text-left flex items-center justify-between md:justify-start">
            Current Mode: <strong id="currentModeDisplay" class="text-primary-blue ml-2">{{ current_mode }}</strong>
            <button id="toggleModeBtn" onclick="toggleMode()" class="ml-4 px-3 py-1 text-xs font-bold text-white transition rounded-full 
            {% if current_mode == MODE_SIMULATION %}bg-warning-orange hover:bg-yellow-600{% else %}bg-primary-blue hover:bg-blue-600{% endif %}">
                Switch to {{ 'Live' if current_mode == MODE_SIMULATION else 'Demo' }}
            </button>
        </div>

        <!-- Controls -->
        <div class="flex space-x-3 w-full md:w-auto">
            <button id="startBtn" onclick="controlSession('start')" class="px-4 py-2 bg-success-green text-white font-semibold rounded-lg hover:bg-green-600 transition disabled:bg-gray-400">Start</button>
            <button id="pauseBtn" onclick="togglePauseUpdates()" class="px-4 py-2 bg-warning-orange text-white font-semibold rounded-lg hover:bg-yellow-600 transition">Pause Updates</button>
            <button id="stopBtn" onclick="controlSession('stop')" class="px-4 py-2 bg-high-red text-white font-semibold rounded-lg hover:bg-red-600 transition disabled:bg-gray-400">Stop</button>
            <button id="resetBtn" onclick="controlSession('reset')" class="px-4 py-2 bg-gray-500 text-white font-semibold rounded-lg hover:bg-gray-600 transition">Reset Counters</button>
        </div>
        
        <!-- Session Timer Display -->
        <div class="text-sm font-medium text-gray-600 border border-gray-200 p-2 rounded-lg w-full md:w-auto text-center md:text-left">
            Session Uptime: <strong id="sessionTimer" class="text-gray-900">
                {{ "%02d"|format(metrics.uptime // 3600) }}:{{ "%02d"|format((metrics.uptime % 3600) // 60) }}:{{ "%02d"|format(metrics.uptime % 60) }}
            </strong>
        </div>
    </div>

    <!-- Metric Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        
        <!-- Total Packets -->
        <div class="bg-white p-5 rounded-xl shadow-lg border-b-4 border-primary-blue">
            <div class="flex justify-between items-center">
                <span class="text-sm font-medium text-gray-500">Total Packets</span>
                <svg class="w-6 h-6 text-primary-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m-8-4v10l8 4m8-10v10l-8 4"></path></svg>
            </div>
            <p id="cardTotalPackets" class="mt-1 text-3xl font-bold text-gray-900">{{ metrics.total_packets }}</p>
        </div>

        <!-- Total Attacks -->
        <div class="bg-white p-5 rounded-xl shadow-lg border-b-4 border-high-red">
            <div class="flex justify-between items-center">
                <span class="text-sm font-medium text-gray-500">Total Attacks</span>
                <svg class="w-6 h-6 text-high-red" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.318 16c-.77 1.333.192 3 1.732 3z"></path></svg>
            </div>
            <p id="cardTotalAttacks" class="mt-1 text-3xl font-bold text-gray-900">{{ metrics.total_attacks }}</p>
        </div>

        <!-- Highest Severity -->
        <div class="bg-white p-5 rounded-xl shadow-lg border-b-4 border-warning-orange">
            <div class="flex justify-between items-center">
                <span class="text-sm font-medium text-gray-500">Highest Threat</span>
                <svg class="w-6 h-6 text-warning-orange" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
            </div>
            <p id="cardHighestThreat" class="mt-1 text-3xl font-bold text-gray-900">{{ metrics.highest_severity }}</p>
        </div>

        <!-- Normal Traffic % -->
        <div class="bg-white p-5 rounded-xl shadow-lg border-b-4 border-success-green">
            <div class="flex justify-between items-center">
                <span class="text-sm font-medium text-gray-500">Normal Traffic</span>
                <svg class="w-6 h-6 text-success-green" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.192-2.058-.512-3.04z"></path></svg>
            </div>
            <p id="cardNormalPercent" class="mt-1 text-3xl font-bold text-gray-900">{{ metrics.normal_percent }}</p>
        </div>
    </div>

    <!-- Real-time Packet Table -->
    <div class="bg-white p-6 rounded-xl shadow-lg overflow-x-auto">
        <h3 class="text-lg font-semibold text-gray-700 mb-4">Real-time Live Feed (100 Recent Packets)</h3>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Time</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Src IP</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dst IP</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attack</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                </tr>
            </thead>
            <tbody id="liveFeedBody" class="bg-white divide-y divide-gray-200">
                <!-- Initial packets from the backend -->
                {% for packet in metrics.live_packets %}
                <tr class="hover:bg-gray-50">
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ packet.time }}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ packet.src_ip }}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ packet.dst_ip }}</td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                        {% if packet.severity == 'High' %}bg-red-100 text-high-red{% elif packet.severity == 'Warning' %}bg-yellow-100 text-warning-orange{% else %}bg-gray-100 text-normal-grey{% endif %}">
                            {{ packet.attack }}
                        </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                        {% if packet.action == 'Block' %}
                        <button data-ip="{{ packet.src_ip }}" onclick="openBlockModal('{{ packet.src_ip }}')" class="bg-high-red text-white text-xs font-bold py-1 px-3 rounded-lg hover:bg-red-600 transition">
                            Block
                        </button>
                        {% else %}
                        -
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</div>

<!-- ATTACK GRAPHS TAB CONTENT (Simplified) -->
<div id="attackGraphs" class="tab-content mt-6 space-y-6">
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Attack Distribution (Doughnut) -->
        <div class="bg-white p-6 rounded-xl shadow-lg">
            <h3 class="text-lg font-semibold text-gray-700 mb-4">Attack Distribution</h3>
            <div style="height: 300px;"><canvas id="attackDistributionChart"></canvas></div>
        </div>
        
        <!-- Uptime Status (Small Donut/Ring) -->
        <div class="bg-white p-6 rounded-xl shadow-lg flex flex-col items-center justify-center">
            <h3 class="text-lg font-semibold text-gray-700 mb-6">Current Session Uptime Status</h3>
            <div class="w-48 h-48 relative">
                <canvas id="uptimeStatusChart"></canvas>
                <div class="absolute inset-0 flex flex-col items-center justify-center">
                    <span id="uptimeDisplay" class="text-2xl font-bold text-primary-blue">
                        {{ "%02d"|format(metrics.uptime // 3600) }}:{{ "%02d"|format((metrics.uptime % 3600) // 60) }}:{{ "%02d"|format(metrics.uptime % 60) }}
                    </span>
                    <span class="text-sm text-gray-500">H:M:S</span>
                </div>
            </div>
        </div>
    </div>
</div>


<script>
    // --- MODE CONSTANTS ---
    const MODE_SIMULATION = 'Demo (Simulated Traffic)';
    const MODE_LIVE = 'Live (Conceptual Network Capture)';

    // Global chart objects (Simplified to only keep the working charts)
    let distChart, uptimeChart;

    // initialMetrics is used for initial chart configuration
    const initialMetrics = {{ metrics | tojson | safe }}; 
    
    // --- UTILITIES ---
    function formatTime(seconds) {
        const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
        const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
        const s = String(seconds % 60).padStart(2, '0');
        return `${h}:${m}:${s}`;
    }

    function getSeverityColors(attack) {
        switch (attack) {
            case 'DoS':
            case 'Bot':
            case 'Infiltration':
                return { text: 'text-high-red', bg: 'bg-red-100', color: '#ef4444' }; // High
            case 'BruteForce':
            case 'PortScan':
                return { text: 'text-warning-orange', bg: 'bg-yellow-100', color: '#f59e0b' }; // Warning
            default:
                return { text: 'text-normal-grey', bg: 'bg-gray-100', color: '#9ca3af' }; // Normal
        }
    }

    // --- CHART INITIALIZATION ---

    // 1. Attack Distribution Chart (Doughnut)
    function initDistChart(labels, counts, colors) {
        const ctx = document.getElementById('attackDistributionChart').getContext('2d');
        if (distChart) distChart.destroy();
        distChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: colors,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false, 
                animation: { duration: 500 },
                plugins: {
                    legend: { position: 'right' },
                    title: { display: false }
                }
            }
        });
    }

    // 2. Uptime Status Chart (Doughnut)
    function initUptimeChart(initialUptime) {
        const uptimeSecondsInDay = initialUptime % 86400; 
        const uptimePercent = (uptimeSecondsInDay / 86400) * 100;
        
        const ctx = document.getElementById('uptimeStatusChart').getContext('2d');
        if (uptimeChart) uptimeChart.destroy();

        uptimeChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Uptime', 'Remaining'],
                datasets: [{
                    data: [uptimePercent, 100 - uptimePercent],
                    backgroundColor: ['#3b82f6', '#e5e7eb'],
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '80%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: false }
                }
            }
        });
    }
    
    // Centralized chart initialization function (Only initializes the remaining two)
    function initializeAllCharts(metrics) {
        const attackLabels = metrics.attack_distribution.map(item => item[0]);
        const attackCounts = metrics.attack_distribution.map(item => item[1]);
        const attackColors = attackLabels.map(label => getSeverityColors(label).color);

        initDistChart(attackLabels, attackCounts, attackColors);
        initUptimeChart(metrics.uptime);
    }


    // Initialize all charts on load
    window.onload = function() {
        // We only initialize charts on load if the *Attack Graphs* tab is made the default.
        // Note: Charts might initialize to 0x0 size here if the container is hidden.
        initializeAllCharts(initialMetrics); 
    };

    // --- REAL-TIME UPDATES (SSE) ---
    
    let eventSource;
    let isUpdatesPaused = false;

    function startSSE() {
        if (eventSource) {
            eventSource.close();
            eventSource = null; // Ensure we start a new one
        }
        eventSource = new EventSource("{{ url_for('live_data_stream') }}");
        eventSource.onmessage = handleSSEMessage;
        eventSource.onerror = (e) => {
            console.error("SSE Error: Attempting to reconnect...", e);
            // Attempt to reconnect after a delay on error
            setTimeout(startSSE, 3000); 
        };
        console.log("SSE Listener Started.");
    }

    function stopSSE() {
        if (eventSource) {
            eventSource.close();
            eventSource = null;
            console.log("SSE Listener Stopped.");
        }
    }
    
    // Start SSE on page load by default (Only if we are on the dashboard)
    if (document.getElementById('liveFeedBody')) {
        startSSE(); 
    }

    function handleSSEMessage(event) {
        if (isUpdatesPaused) return;

        try {
            const data = JSON.parse(event.data);
            const packet = data.packet;
            const metrics = data.metrics;

            // 1. Update Metrics Cards
            document.getElementById('cardTotalPackets').textContent = metrics.total_packets.toLocaleString();
            document.getElementById('cardTotalAttacks').textContent = metrics.total_attacks.toLocaleString();
            document.getElementById('cardHighestThreat').textContent = metrics.highest_severity;
            document.getElementById('cardNormalPercent').textContent = metrics.normal_percent;
            
            // 2. Update Session Timer
            document.getElementById('sessionTimer').textContent = formatTime(metrics.uptime);
            document.getElementById('uptimeDisplay').textContent = formatTime(metrics.uptime);

            // 3. Update Live Feed Table
            if (document.getElementById('liveFeedBody')) {
                updateLiveTable(packet);
            }

            // 4. Update Charts
            updateCharts(metrics);
        } catch (e) {
            console.error("Error processing SSE message:", e);
        }
    }

    function updateLiveTable(packet) {
        const tableBody = document.getElementById('liveFeedBody');
        
        // Create new row
        const newRow = tableBody.insertRow(0); // Insert at the top
        newRow.classList.add('hover:bg-gray-50');

        const colors = getSeverityColors(packet.attack);
        
        newRow.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">${packet.time}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.src_ip}</td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${packet.dst_ip}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${colors.bg} ${colors.text}">
                    ${packet.attack}
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                ${packet.action === 'Block' ? 
                    `<button data-ip="${packet.src_ip}" onclick="openBlockModal('${packet.src_ip}')" class="bg-high-red text-white text-xs font-bold py-1 px-3 rounded-lg hover:bg-red-600 transition">Block</button>` 
                    : '-'}
            </td>
        `;

        // Maintain max 100 rows
        if (tableBody.rows.length > 100) {
            tableBody.deleteRow(100); 
        }
    }

    function updateCharts(metrics) {
        // Only check for the remaining two charts
        if (!distChart || !uptimeChart) {
            // If charts are not initialized, skip update.
            return;
        }
        
        // 1. Attack Distribution Chart (Doughnut)
        const labels = [];
        const data = [];
        const colors = [];
        metrics.attack_distribution.forEach(([label, count]) => {
            labels.push(label);
            data.push(count);
            colors.push(getSeverityColors(label).color);
        });

        distChart.data.labels = labels;
        distChart.data.datasets[0].data = data;
        distChart.data.datasets[0].backgroundColor = colors;
        distChart.update('none'); // Use 'none' for faster redraw


        // 2. Uptime Status Chart (Doughnut)
        const uptimeSecondsInDay = metrics.uptime % 86400; 
        const uptimePercent = (uptimeSecondsInDay / 86400) * 100;
        uptimeChart.data.datasets[0].data = [uptimePercent, 100 - uptimePercent];
        uptimeChart.update('none');
    }
    
    function togglePauseUpdates() {
        isUpdatesPaused = !isUpdatesPaused;
        const button = document.getElementById('pauseBtn');
        if (isUpdatesPaused) {
            button.textContent = 'Resume Updates';
            button.classList.remove('bg-warning-orange');
            button.classList.add('bg-success-green');
        } else {
            button.textContent = 'Pause Updates';
            button.classList.remove('bg-success-green');
            button.classList.add('bg-warning-orange');
        }
    }
    
    // Function to perform client-side state reset
    function clientSideReset() {
        document.getElementById('liveFeedBody').innerHTML = '';
        document.getElementById('cardTotalPackets').textContent = '0';
        document.getElementById('cardTotalAttacks').textContent = '0';
        document.getElementById('cardHighestThreat').textContent = 'Normal';
        document.getElementById('cardNormalPercent').textContent = '0.0%';
        document.getElementById('sessionTimer').textContent = '00:00:00';
        document.getElementById('uptimeDisplay').textContent = '00:00:00';

        // Destroy and reinitialize remaining charts with zero/empty data 
        initializeAllCharts({
            total_packets: 0,
            uptime: 0,
            attack_distribution: initialMetrics.attack_distribution.map(([label]) => [label, 0]),
            top_ips: [] // Still needed in initialMetrics structure, but not used by init functions
        });
    }


    // --- MODE TOGGLE ---

    async function toggleMode() {
        try {
            const response = await fetch('/control/toggle_mode', { method: 'POST' });
            const result = await response.json();
            
            console.log(result.message);
            
            // 1. Update UI display
            const currentModeDisplay = document.getElementById('currentModeDisplay');
            const toggleModeBtn = document.getElementById('toggleModeBtn');
            
            currentModeDisplay.textContent = result.new_mode;

            if (result.new_mode === MODE_LIVE) {
                toggleModeBtn.textContent = 'Switch to Demo';
                toggleModeBtn.classList.remove('bg-warning-orange');
                toggleModeBtn.classList.add('bg-primary-blue');
            } else {
                toggleModeBtn.textContent = 'Switch to Live';
                toggleModeBtn.classList.remove('bg-primary-blue');
                toggleModeBtn.classList.add('bg-warning-orange');
            }
            
            // 2. Perform client-side reset and restart SSE
            clientSideReset();
            startSSE(); // SSE will immediately try to connect to the newly reset backend thread
            
        } catch (error) {
            console.error('Error toggling mode:', error);
        }
    }


    // --- SESSION CONTROL ---
    async function controlSession(action) {
        try {
            const response = await fetch(`/control/${action}`, { method: 'POST' });
            const result = await response.json();
            console.log(result.message || result.status);
            
            if (action === 'start' || action === 'resume') {
                startSSE();
            } else if (action === 'stop') {
                stopSSE();
            } else if (action === 'reset') {
                // Perform client-side reset and restart SSE
                clientSideReset();
                startSSE();
            }
        } catch (error) {
            console.error(`Error controlling session (${action}):`, error);
        }
    }

    // --- TAB SWITCHING LOGIC (Simplified) ---
    function switchTab(tabId) {
        document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');

        document.querySelectorAll('.tab-link').forEach(link => {
            link.classList.remove('active-tab', 'border-primary-blue', 'text-primary-blue');
            link.classList.add('border-transparent', 'text-gray-500', 'hover:text-gray-700', 'hover:border-gray-300');
        });

        const activeLink = document.querySelector(`[onclick="switchTab('${tabId}')"]`);
        if (activeLink) {
            activeLink.classList.add('active-tab', 'border-primary-blue', 'text-primary-blue');
            activeLink.classList.remove('border-transparent', 'text-gray-500', 'hover:text-gray-700', 'hover:border-gray-300');
        }

        // --- CHART FIX: Ensure charts are initialized and redrawn when visible ---
        if (tabId === 'attackGraphs') {
            
            // Critical Step 1: If charts haven't been successfully initialized (i.e., they are null), 
            // force the initialization now that the container is visible.
            if (!distChart) {
                console.log("Charts not initialized. Forcing re-initialization now that container is visible.");
                initializeAllCharts(initialMetrics); 
            }

            // Critical Step 2: Always force redraw and resize when the tab becomes visible
            // This ensures Chart.js recalculates dimensions based on the now-visible container.
            if (distChart) {
                distChart.resize();
                distChart.update('none'); 
            }
            if (uptimeChart) {
                uptimeChart.resize();
                uptimeChart.update('none');
            }
        }
    }
</script>
"""

# Report Content (Unchanged)
REPORT_CONTENT = """
<div class="space-y-6">
    <div class="flex justify-between items-center mb-6">
        <h2 class="text-2xl font-bold text-gray-800">Security Summary Report</h2>
        <!-- Button to trigger print function (simulates PDF export) -->
        <button onclick="window.print()" class="no-print px-4 py-2 bg-primary-blue text-white font-semibold rounded-lg hover:bg-blue-600 transition">
            <svg class="w-4 h-4 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4m14 0l-12 0"></path></svg>
            Download Summary (Print/PDF)
        </button>
    </div>

    <!-- Generated Report Content from LLM (Injected by Flask) -->
    <div id="report-output" class="report-content">
        {{ report_html | safe }}
    </div>
</div>
"""
# Alerts Content (Unchanged)
ALERTS_CONTENT = """
<div class="space-y-6">
    <!-- Header and Controls -->
    <div class="bg-white p-4 rounded-xl shadow-lg flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
        
        <!-- Search and Filter -->
        <div class="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 w-full md:w-auto">
            <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search IP or Attack Type..." class="w-full sm:w-64 p-2 border border-gray-300 rounded-lg focus:ring-primary-blue focus:border-primary-blue">
            
            <select id="attackTypeFilter" onchange="filterTable()" class="p-2 border border-gray-300 rounded-lg w-full sm:w-40">
                <option value="">All Types</option>
                <option value="DoS">DoS</option>
                <option value="BruteForce">BruteForce</option>
                <option value="Bot">Bot</option>
                <option value="PortScan">PortScan</option>
                <option value="Infiltration">Infiltration</option>
                <option value="Normal">Normal</option>
            </select>
        </div>

        <!-- Export Button -->
        <a href="{{ url_for('export_alerts') }}" class="w-full md:w-auto px-4 py-2 bg-primary-blue text-white font-semibold rounded-lg hover:bg-blue-600 transition text-center">
            <svg class="w-4 h-4 inline-block mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
            Export as CSV
        </a>
    </div>

    <!-- Historical Alerts Table -->
    <div class="bg-white p-6 rounded-xl shadow-lg overflow-x-auto">
        <h3 class="text-lg font-semibold text-gray-700 mb-4">Historical Event Log ({{ alerts_data | length }} Events)</h3>
        
        <table id="alertsTable" class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onclick="sortTable(0)">Time</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onclick="sortTable(1)">Src IP</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Dst IP</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onclick="sortTable(3)">Attack</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer" onclick="sortTable(4)">Severity</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody id="alertsTableBody" class="bg-white divide-y divide-gray-200">
                {% for alert in alerts_data | reverse %}
                <tr class="hover:bg-gray-50">
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{{ alert.time }}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ alert.src_ip }}</td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{{ alert.dst_ip }}</td>
                    <td class="px-6 py-4 whitespace-nowrap">
                        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full 
                        {% if alert.severity == 'High' %}bg-red-100 text-high-red{% elif alert.severity == 'Warning' %}bg-yellow-100 text-warning-orange{% else %}bg-gray-100 text-normal-grey{% endif %}">
                            {{ alert.attack }}
                        </span>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-700">
                        {{ alert.severity }}
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap space-x-2">
                        {% if alert.attack != 'Normal' %}
                        <button data-ip="{{ alert.src_ip }}" onclick="openBlockModal('{{ alert.src_ip }}')" class="bg-high-red text-white text-xs font-bold py-1 px-3 rounded-lg hover:bg-red-600 transition">
                            Block IP
                        </button>
                        {% endif %}
                        <button data-id="{{ alert.id }}" onclick="markReviewed(this)" class="bg-gray-200 text-gray-700 text-xs font-bold py-1 px-3 rounded-lg hover:bg-gray-300 transition review-btn">
                            Mark as Reviewed
                        </button>
                    </td>
                </tr>
                {% endfor %}
                {% if not alerts_data %}
                <tr>
                    <td colspan="6" class="px-6 py-8 text-center text-gray-500">No historical alerts found. Start the live feed to generate data.</td>
                </tr>
                {% endif %}
            </tbody>
        </table>
    </div>
</div>

<script>
    function markReviewed(buttonElement) {
        buttonElement.textContent = 'REVIEWED';
        buttonElement.classList.remove('bg-gray-200', 'hover:bg-gray-300');
        buttonElement.classList.add('bg-success-green', 'text-white', 'cursor-default');
        buttonElement.disabled = true;
    }
    
    // --- Filtering and Searching Logic ---
    function filterTable() {
        const searchInput = document.getElementById('searchInput').value.toUpperCase();
        const attackFilter = document.getElementById('attackTypeFilter').value.toUpperCase();
        const tableBody = document.getElementById('alertsTableBody');
        const rows = tableBody.getElementsByTagName('tr');

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];
            const srcIp = row.cells[1] ? row.cells[1].textContent.toUpperCase() : '';
            const dstIp = row.cells[2] ? row.cells[2].textContent.toUpperCase() : '';
            const attackTypeCell = row.cells[3] ? row.cells[3].querySelector('span').textContent.toUpperCase().trim() : '';
            
            // 1. Check Search Input (IP or Attack Type)
            const searchMatch = (srcIp.includes(searchInput) || dstIp.includes(searchInput) || attackTypeCell.includes(searchInput));
            
            // 2. Check Dropdown Filter
            const attackFilterMatch = (attackFilter === '' || attackTypeCell === attackFilter);

            if (searchMatch && attackFilterMatch) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        }
    }

    // --- Sorting Logic ---
    let sortDirection = 1; // 1 for ascending, -1 for descending
    let lastSortedColumn = -1;

    function sortTable(columnIndex) {
        let table, rows, switching, i, x, y, shouldSwitch;
        table = document.getElementById("alertsTable");
        switching = true;
        
        if (lastSortedColumn !== columnIndex) {
            sortDirection = 1; // Reset to ascending for new column
        } else {
            sortDirection *= -1; // Toggle direction
        }
        lastSortedColumn = columnIndex;

        while (switching) {
            switching = false;
            rows = table.rows;
            for (i = 1; i < (rows.length - 1); i++) {
                shouldSwitch = false;
                
                x = rows[i].getElementsByTagName("TD")[columnIndex];
                y = rows[i + 1].getElementsByTagName("TD")[columnIndex];

                let xValue = x.textContent.toLowerCase().trim();
                let yValue = y.textContent.toLowerCase().trim();
                
                // Determine comparison logic
                if (columnIndex === 0) { // Time column
                    // Simple string comparison for HH:MM:SS is usually fine for time of day
                    if (sortDirection === 1) {
                        if (xValue > yValue) { shouldSwitch = true; break; }
                    } else {
                        if (xValue < yValue) { shouldSwitch = true; break; }
                    }
                } else {
                    // General text comparison
                    if (sortDirection === 1) {
                        if (xValue > yValue) { shouldSwitch = true; break; }
                    } else {
                        if (xValue < yValue) { shouldSwitch = true; break; }
                    }
                }
            }
            if (shouldSwitch) {
                rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                switching = true;
            }
        }
    }

</script>
"""
# --- Flask App Initialization & Routes ---
app = Flask(__name__)
app.name = 'app1' 

# Set up a simple event loop for the async function calls
loop = asyncio.get_event_loop()

def render_full_page(title, content_template, **context):
    """Combines the base template with the content template for rendering."""
    full_html = BASE_TEMPLATE.replace('{{ content }}', content_template)
    return render_template_string(full_html, title=title, **context)


@app.route('/')
def index():
    """Renders the main dashboard page."""
    metrics = data_store.get_metrics()
    # Pass mode constants and current mode to template
    return render_full_page("Dashboard", DASHBOARD_CONTENT, 
                            metrics=metrics, 
                            current_mode=current_mode,
                            MODE_SIMULATION=MODE_SIMULATION,
                            MODE_LIVE=MODE_LIVE)

@app.route('/alerts')
def alerts():
    """Renders the historical alerts manager page."""
    alerts_data = data_store.historical_alerts
    return render_full_page("Alerts Manager", ALERTS_CONTENT, alerts_data=alerts_data)

@app.route('/report')
def report():
    """Renders the Security Report page and synchronously generates report content."""
    metrics = data_store.get_metrics()
    
    # Prepare data for the LLM
    top_ips_summary = [
        {"ip": ip, "count": count} 
        for ip, count in metrics['top_ips'][:3]
    ]

    # Synchronously call the async LLM function using the event loop
    try:
        report_md = loop.run_until_complete(generate_nids_report(metrics, top_ips_summary))
        
        # FIX: Strip leading/trailing whitespace before conversion
        report_html = report_md.strip() 

        # Simple Markdown to HTML conversion
        # Convert H2 (##) and H3 (###) to <h3> and then clean up the resulting HTML for spacing
        report_html = report_html.replace('## Executive Security Report:', '<h3>Executive Security Report:</h3>')
        report_html = report_html.replace('**', '<strong>')
        report_html = report_html.replace('`', '<code>')
        
        # Convert newlines to paragraphs
        report_html = '<p>' + report_html.replace('\n\n', '</p><p>') + '</p>'
        
        # Clean up tags that might have been wrapped incorrectly by the paragraph conversion
        report_html = report_html.replace('<p><h3>', '<h3>').replace('</h3></p>', '</h3>')
        report_html = report_html.replace('</p><p><h3>', '<h3>').replace('</h3>', '</h3><p>')
        
        # Final cleanup for the very first element's leading <p> tag if it wraps a header
        if report_html.startswith('<p><h3>'):
             report_html = report_html.replace('<p><h3>', '<h3>', 1)
        if report_html.endswith('</h3><p></p>'):
            report_html = report_html[:-len('<p></p>')]


    except Exception as e:
        report_html = f'<div class="text-center py-12 text-high-red font-medium">Report Generation Service Error: {str(e)}</div>'

    # Render the report page with the generated HTML content
    return render_full_page("Security Report", REPORT_CONTENT, report_html=report_html)


@app.route('/live_data_stream')
def live_data_stream():
    """Server-Sent Events (SSE) endpoint for real-time updates."""
    def generate():
        last_packet_count = data_store.total_packets
        while data_store.session_running.is_set():
            # Check if the capture thread has stopped unexpectedly
            if not capture_thread.is_alive():
                time.sleep(1) # Give it a moment, then check again
                if not capture_thread.is_alive():
                    # If it's still dead but the session is marked running, something went wrong.
                    # We can't restart here safely in SSE, just skip sending data until control is hit.
                    time.sleep(5) 
                    continue


            if data_store.total_packets > last_packet_count:
                # Update the packet count and get all metrics
                last_packet_count = data_store.total_packets
                metrics = data_store.get_metrics()
                
                # The latest packet is always at index 0 of live_packets deque
                latest_packet = metrics["live_packets"][0] if metrics["live_packets"] else None
                
                if latest_packet:
                    realtime_data = {
                        "packet": latest_packet,
                        "metrics": metrics
                    }
                    # Send JSON object containing both the new packet and updated metrics
                    yield f"data: {json.dumps(realtime_data)}\n\n"
            
            time.sleep(0.5) # Poll for new data every half second

    return Response(generate(), mimetype='text/event-stream')

# --- Mode Control Endpoint ---
@app.route('/control/toggle_mode', methods=['POST'])
def toggle_mode_endpoint():
    """Toggles between simulation and live modes."""
    global current_mode
    global capture_thread
    
    # 1. Determine new mode
    new_mode = MODE_LIVE if current_mode == MODE_SIMULATION else MODE_SIMULATION
    
    # 2. Stop the current thread gracefully
    data_store.session_running.clear()
    
    # 3. Wait for the old thread to terminate (safer cleanup)
    if capture_thread.is_alive():
         capture_thread.join(timeout=1) # Wait up to 1 second
    
    # 4. Reset all data (since mode change implies a new session/context)
    data_store.reset_counters()
    
    # 5. Update mode
    current_mode = new_mode

    # 6. Start a new thread immediately with the new mode's function (optional, but starts data flow immediately)
    data_store.session_running.set() # Reset the running flag
    capture_target = start_live_capture if current_mode == MODE_LIVE else start_demo_capture
    capture_thread = threading.Thread(target=capture_target, args=(data_store,), daemon=True)
    capture_thread.start()

    return jsonify({
        "status": "Success", 
        "new_mode": current_mode, 
        "message": f"Switched to {current_mode}. Counters reset. Data capture thread restarted."
    })


# --- Session Control Endpoints ---

@app.route('/control/<action>', methods=['POST'])
def control_session(action):
    """Handles Start/Stop/Pause/Resume/Reset actions."""
    # FIX: Global declarations MUST be the first lines in the function (resolves SyntaxError)
    global capture_thread 
    global current_mode

    # Determine which capture function to use based on current mode
    capture_target = start_live_capture if current_mode == MODE_LIVE else start_demo_capture
    
    if action == 'stop':
        data_store.session_running.clear()
        
    elif action == 'start' or action == 'resume':
        if not data_store.session_running.is_set():
            data_store.session_running.set()
            # If the thread is dead, restart it with the appropriate target function
            if not capture_thread.is_alive():
                 # Create a brand new thread object with the correct target function
                 capture_thread = threading.Thread(target=capture_target, args=(data_store,), daemon=True)
                 capture_thread.start()
            
    elif action == 'reset':
        data_store.session_running.clear() # Stop old thread first
        if capture_thread.is_alive():
             capture_thread.join(timeout=1) # Wait for it to join

        data_store.reset_counters()

        # Start a new thread with the current mode's function
        data_store.session_running.set() # Reset the running flag
        capture_thread = threading.Thread(target=capture_target, args=(data_store,), daemon=True)
        capture_thread.start()

    return jsonify({"status": f"Session {action}d", "action": action, "running": data_store.session_running.is_set(), "message": f"NIDS session counters {action} successfully. Data stream will restart now in {current_mode}."})

@app.route('/block_ip/<ip_address>', methods=['POST'])
def block_ip(ip_address):
    """Simulates blocking an IP address."""
    # Log the action in the console
    print(f"Firewall Rule Added: Blocking IP {ip_address}")
    return jsonify({'status': 'Blocked', 'ip': ip_address, 'message': f'IP {ip_address} permanently blocked.'})

@app.route('/alerts/export', methods=['GET'])
def export_alerts():
    """Exports all historical alerts as a CSV file."""
    si = StringIO()
    cw = csv.writer(si)
    
    # Define CSV header
    header = ["ID", "Time", "Source IP", "Destination IP", "Attack Type", "Severity", "Action"]
    cw.writerow(header)

    # Write data rows
    for log in data_store.historical_alerts:
        cw.writerow([
            log['id'],
            log['time'],
            log['src_ip'],
            log['dst_ip'],
            log['attack'],
            log['severity'],
            log['action']
        ])

    output = si.getvalue()
    
    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=nids_alerts_export.csv"
    return response

# --- Run App ---
if __name__ == '__main__':
    # Set thread safety for reloader
    app.run(debug=True, threaded=True, use_reloader=False) 
