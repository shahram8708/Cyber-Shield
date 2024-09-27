from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
import urllib.parse
import threading

app = Flask(__name__)

xss_test_payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>"
]
sql_injection_test_payloads = [
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' UNION SELECT NULL, username, password FROM users --",
    "'; DROP TABLE users; --"
]
csrf_token_names = ['csrf', 'token', 'xsrf', 'csrf_token']

lock = threading.Lock()

def explain_vulnerability(vuln_type):
    explanations = {
        'SQL Injection': {
            'risk': 'SQL Injection allows an attacker to interfere with the queries that an application makes to its database.',
            'impact': 'An attacker can read sensitive data, modify data, execute administrative operations, or even issue commands to the operating system.',
            'remediation': 'Use parameterized queries and prepared statements. Implement proper input validation and output encoding.'
        },
        'XSS': {
            'risk': 'Cross-Site Scripting (XSS) enables attackers to inject malicious scripts into web pages viewed by other users.',
            'impact': 'It can lead to session hijacking, defacement, and redirecting users to malicious sites.',
            'remediation': 'Implement content security policies (CSP) and validate/encode user inputs.'
        },
        'CSRF': {
            'risk': 'Cross-Site Request Forgery (CSRF) forces a user to execute unwanted actions on a web application where they are authenticated.',
            'impact': 'It can result in unwanted transactions or data modification without user consent.',
            'remediation': 'Use anti-CSRF tokens and ensure that state-changing requests are protected.'
        },
        'Open Redirect': {
            'risk': 'Open Redirect allows an attacker to redirect users to any URL, potentially leading to phishing attacks.',
            'impact': 'Users may be tricked into visiting malicious sites, resulting in credential theft or malware installation.',
            'remediation': 'Avoid redirecting users to arbitrary URLs and validate redirect URLs against a whitelist.'
        },
        'SSRF': {
            'risk': 'Server-Side Request Forgery (SSRF) allows an attacker to send crafted requests from the server, potentially accessing internal services.',
            'impact': 'It can expose sensitive data and internal systems that should not be accessible externally.',
            'remediation': 'Validate and sanitize URLs that are allowed to be fetched and implement network access controls.'
        }
    }
    return explanations.get(vuln_type, {})

def test_sql_injection(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    vulnerabilities = []

    for param in query_params:
        for payload in sql_injection_test_payloads:
            injected_query_params = query_params.copy()
            injected_query_params[param] = payload
            injected_query = urllib.parse.urlencode(injected_query_params, doseq=True)
            injected_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, injected_query, parsed_url.fragment))

            try:
                response = requests.get(injected_url, timeout=5)
                if ("error" in response.text.lower() or "syntax" in response.text.lower() or "mysql" in response.text.lower() or "sql" in response.text.lower()):
                    with lock:
                        vulnerabilities.append(f"SQL Injection: {injected_url}")
            except requests.exceptions.RequestException as e:
                pass

    return vulnerabilities

def test_xss(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    vulnerabilities = []

    forms = soup.find_all('form')
    for form in forms:
        form_action = form.get('action')
        form_method = form.get('method', 'get').lower()
        form_data = {}

        inputs = form.find_all('input')
        for input_tag in inputs:
            input_name = input_tag.get('name')
            if input_name:
                for payload in xss_test_payloads:
                    form_data[input_name] = payload

                    form_action_url = urllib.parse.urljoin(url, form_action)
                    if form_method == 'post':
                        response = requests.post(form_action_url, data=form_data)
                    else:
                        response = requests.get(form_action_url, params=form_data)

                    if payload in response.text:
                        with lock:
                            vulnerabilities.append(f"XSS: {form_action_url} with payload: {payload}")

    return vulnerabilities

def test_csrf(url):
    vulnerabilities = []
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    for form in forms:
        form_action = form.get('action')
        inputs = form.find_all('input')
        tokens = [input_tag.get('name') for input_tag in inputs if input_tag.get('type') == 'hidden' and input_tag.get('name') in csrf_token_names]
        
        if not tokens:
            with lock:
                vulnerabilities.append(f"CSRF: {form_action} may be vulnerable (no CSRF token found).")
    
    return vulnerabilities

def test_open_redirect(url):
    vulnerabilities = []
    malicious_redirect_url = "http://malicious-website.com"
    
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)

    for param in query_params:
        injected_query_params = query_params.copy()
        injected_query_params[param] = malicious_redirect_url
        injected_query = urllib.parse.urlencode(injected_query_params, doseq=True)
        injected_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, injected_query, parsed_url.fragment))

        try:
            response = requests.get(injected_url, timeout=5)
            if response.url.startswith(malicious_redirect_url):
                with lock:
                    vulnerabilities.append(f"Open Redirect: {injected_url}")
        except requests.exceptions.RequestException as e:
            pass

    return vulnerabilities

def test_ssrf(url):
    vulnerabilities = []
    malicious_url = "http://169.254.169.254/latest/meta-data/"
    
    try:
        response = requests.get(malicious_url, timeout=5)
        if response.status_code == 200:
            with lock:
                vulnerabilities.append(f"SSRF: Possible SSRF vulnerability with URL: {malicious_url}")
    except requests.exceptions.RequestException as e:
        pass

    return vulnerabilities

def scan_url(url):
    vulnerabilities = []

    threads = []
    functions = [test_sql_injection, test_xss, test_csrf, test_open_redirect, test_ssrf]

    for func in functions:
        thread = threading.Thread(target=lambda f=func: vulnerabilities.extend(f(url)))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return vulnerabilities

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target_url = request.form['url']
        vulnerabilities = scan_url(target_url)

        results = []
        for vuln in vulnerabilities:
            vuln_type = vuln.split(":")[0].strip()
            explanation = explain_vulnerability(vuln_type)
            result = {
                'description': vuln,
                'risk': explanation['risk'],
                'impact': explanation['impact'],
                'remediation': explanation['remediation']
            }
            results.append(result)
        
        return render_template('results.html', results=results, target_url=target_url)
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
