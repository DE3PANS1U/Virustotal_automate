import os
from flask import Flask, request, jsonify, render_template
import requests
import pandas as pd
import time

app = Flask(__name__)

API_KEY = '64d7d06aa998e956f477df17e005153a3c4ffd4affae3eb036afc21bd65af507'

# Function to check the status of an IP address
def check_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        response_json = response.json()
        data = response_json.get('data', {})
        id_value = data.get('id', 'N/A')
        malicious_value = data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 'N/A')
        as_label = data.get('attributes', {}).get('as_owner', 'N/A')
        
        return {
            "id": id_value,
            "malicious": malicious_value,
            "as_label": as_label
        }
    else:
        return {
            "id": ip,
            "malicious": "Error",
            "as_label": "Error"
        }

# Endpoint to handle IP checks
@app.route('/check_ips', methods=['POST'])
def check_ips():
    ip_addresses = request.json.get("ips", [])
    results = []

    for index, ip in enumerate(ip_addresses):
        result = check_ip(ip)
        results.append(result)
        
        # Respect API rate limit: 4 requests per minute
        if (index + 1) % 4 == 0:
            time.sleep(15)  # Wait 15 seconds

    return jsonify(results)

# Home route to render the HTML page
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
