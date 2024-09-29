

# app.py
from flask import Flask, render_template, request
import dns_resolver, traceroute, ip_lookup, ssl_cert, whois_lookup, web_scrape

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/investigate', methods=['POST'])
def investigate():
    domain = request.form['domain']

    # Phase 1: Network-Based Analysis
    dns_history = dns_resolver.get_dns_history(domain)
    trace_result = traceroute.perform_traceroute(domain)
    ip_info = ip_lookup.lookup_ip(trace_result)

    # Phase 2: OSINT-Based Analysis
    cert_info = ssl_cert.get_certificate_info(domain)
    whois_data = whois_lookup.get_whois_history(domain)
    scrape_result = web_scrape.scrape_website(domain)

    # Combine the results
    result = {
        'dns_history': dns_history,
        'trace_result': trace_result,
        'ip_info': ip_info,
        'cert_info': cert_info,
        'whois_data': whois_data,
        'scrape_result': scrape_result,
    }

    return render_template('results.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)

# dns_resolver.py
import requests

def get_dns_history(domain):
    api_key = "YOUR_SECURITYTRAILS_API_KEY"
    url = f'https://api.securitytrails.com/v1/history/{domain}/dns'
    headers = {'APIKEY': api_key}
    response = requests.get(url, headers=headers)
    return response.json()

# traceroute.py
from scapy.layers.inet import traceroute

def perform_traceroute(domain):
    result, _ = traceroute(domain)
    ip_list = [r[1].src for r in result.res]
    return ip_list

# ip_lookup.py
import requests

def lookup_ip(ip_list):
    ip_data = []
    for ip in ip_list:
        url = f'https://ipinfo.io/{ip}/json'
        response = requests.get(url)
        ip_data.append(response.json())
    return ip_data

# ssl_cert.py
import requests

def get_certificate_info(domain):
    API_ID = "YOUR_CENSYS_API_ID"
    API_SECRET = "YOUR_CENSYS_API_SECRET"
    url = f'https://search.censys.io/api/v2/certificates'
    params = {'q': f'parsed.names: {domain}'}
    response = requests.get(url, auth=(API_ID, API_SECRET), params=params)
    return response.json()

# whois_lookup.py
import requests

def get_whois_history(domain):
    api_key = "YOUR_WHOISXML_API_KEY"
    url = f'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=JSON'
    response = requests.get(url)
    return response.json()

# web_scrape.py
import requests
from bs4 import BeautifulSoup

def scrape_website(domain):
    url = f'http://{domain}'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    images = [img['src'] for img in soup.find_all('img')]
    return images