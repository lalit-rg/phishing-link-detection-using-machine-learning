# 
# import requests

# # URL to target
# target_url = "https://ww4.5movierulz.ac/category/telugu-movies-2023/"  # Replace with the URL you want to test

# # List of common directory names to try
# common_directories = [
#     "admin",
#     "backup",
#     "config",
#     "private",
#     "secret",
#     "hidden",
#     "test",
#     "tmp",
#     "uploads",
#     "web",
# ]

# # Loop through common directory names and check their existence
# for directory in common_directories:
#     full_url = f"{target_url}/{directory}"
#     response = requests.get(full_url)

#     if response.status_code == 200:
#         print(f"Directory '{directory}' exists: {full_url}")
#     elif response.status_code == 403:
#         print(f"Directory '{directory}' is forbidden: {full_url}")
# from selenium import webdriver
# from selenium.webdriver.common.by import By

# # URL to target
# target_url = "https://ww4.5movierulz.ac/category/telugu-movies-2023/"  # Replace with the URL you want to test

# # Set up Selenium WebDriver (you need to install the appropriate driver)
# driver = webdriver.Chrome()  # Use the appropriate driver for your browser

# # Load the target URL
# driver.get(target_url)

# # Check source of iframes
# iframes = driver.find_elements(By.TAG_NAME, "iframe")
# for iframe in iframes:
#     iframe_src = iframe.get_attribute("src")
#     if not iframe_src:
#         print("Found iframe without src attribute")
#     else:
#         if "trusted-domain.com" in iframe_src:
#             print(f"Iframe from trusted source: {iframe_src}")
#         else:
#             print(f"Iframe from untrusted source: {iframe_src}")

# # Check attributes and behavior of iframes
# for iframe in iframes:
#     sandbox_attribute = iframe.get_attribute("sandbox")
#     transparent_bg = iframe.value_of_css_property("background-color")
#     if sandbox_attribute:
#         print("Iframe has sandbox attribute:", sandbox_attribute)
#     if transparent_bg == "rgba(0, 0, 0, 0)":
#         print("Iframe has transparent background, potential overlay attempt")

# # Check X-Frame-Options header
# x_frame_options = driver.execute_script("return window.getComputedStyle(document.body)['x-frame-options']")
# if x_frame_options:
#     print("X-Frame-Options header detected:", x_frame_options)
# else:
#     print("X-Frame-Options header not detected")

# # Check for frame-busting code
# frame_busting_code = driver.execute_script(
#     "(function(){if(window.top!=window.self){return true;}})();"
# )
# if frame_busting_code:
#     print("Frame-busting code detected")

# # Check Content Security Policy (CSP)
# csp_meta_tag = driver.find_element(By.CSS_SELECTOR, "meta[http-equiv='Content-Security-Policy']")
# csp_value = csp_meta_tag.get_attribute("content")
# print("Content Security Policy (CSP):", csp_value)

# # Close the browser
# driver.quit()


# import socket

# def scan_ports(target_host, start_port, end_port):
#     open_ports = []
#     for port in range(start_port, end_port + 1):
#         sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         sock.settimeout(1)  # Set a timeout for the connection attempt
#         result = sock.connect_ex((target_host, port))
#         if result == 0:
#             open_ports.append(port)
#         sock.close()
#     return open_ports

# if __name__ == "__main__":
#     target_host = input("Enter the target host or IP address: ")
#     start_port = int(input("Enter the starting port: "))
#     end_port = int(input("Enter the ending port: "))

#     print(f"Scanning ports {start_port} to {end_port} on {target_host}...")
#     open_ports = scan_ports(target_host, start_port, end_port)

#     if len(open_ports) == 0:
#         print("No open ports found.")
#     else:
#         print("Open ports:")
#         for port in open_ports:
#             print(port)


import socket
import concurrent.futures
from urllib.parse import urlparse

def get_domain_x(url):
    # Extract the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

def scan_ports(target_host, port_list, timeout=1):
    open_ports = []
    
    def scan(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(scan, port_list)
    
    return open_ports

# Example usage
target_host = "www.anits.edu.in"#get_domain_x("www.anits.edu.in")
print(target_host)
ports_to_scan = [21, 22, 80, 443, 3389]  # List of ports to scan

open_ports = scan_ports(target_host, ports_to_scan)
print("Open ports:", open_ports)


port_services = {
    21: "FTP (File Transfer Protocol) - Port 21",
    22: "SSH (Secure Shell) - Port 22",
    23: "Telnet - Port 23",
    25: "SMTP (Simple Mail Transfer Protocol) - Port 25",
    53: "DNS (Domain Name System) - Port 53",
    80: "HTTP (Hypertext Transfer Protocol) - Port 80",
    110: "POP3 (Post Office Protocol 3) - Port 110",
    123: "NTP (Network Time Protocol) - Port 123",
    135: "MS RPC (Microsoft Remote Procedure Call) - Port 135",
    139: "NetBIOS - Port 139",
    143: "IMAP (Internet Message Access Protocol) - Port 143",
    161: "SNMP (Simple Network Management Protocol) - Port 161",
    443: "HTTPS (HTTP Secure) - Port 443",
    445: "Microsoft-DS (Microsoft Directory Services) - Port 445",
    465: "SMTPS (SMTP over TLS/SSL) - Port 465",
    514: "Syslog - Port 514",
    587: "Submission (Email Message Submission) - Port 587",
    993: "IMAPS (IMAP over TLS/SSL) - Port 993",
    995: "POP3S (POP3 over TLS/SSL) - Port 995",
    1433: "MSSQL (Microsoft SQL Server) - Port 1433",
    1521: "Oracle Database Default Listener - Port 1521",
    3306: "MySQL Database - Port 3306",
    3389: "RDP (Remote Desktop Protocol) - Port 3389",
    5432: "PostgreSQL Database - Port 5432",
    5900: "VNC (Virtual Network Computing) - Port 5900",
    5985: "WinRM (Windows Remote Management) - Port 5985",
    6379: "Redis Database - Port 6379",
    6666: "IRC (Internet Relay Chat) - Port 6666",
    6800: "HTTP Proxy (Proxy Servers) - Port 6800",
    8080: "Alternative HTTP Port - Port 8080",
    8888: "Alternative HTTP Port - Port 8888",
    9000: "Alternative HTTP Port - Port 9000",
    9200: "Elasticsearch REST API - Port 9200",
    9418: "Git Version Control System - Port 9418",
    27017: "MongoDB Database - Port 27017",
    27018: "MongoDB Shardsvr - Port 27018",
    27019: "MongoDB Mongos - Port 27019",
    28017: "MongoDB Web Interface - Port 28017",
    33060: "MySQL X Protocol - Port 33060",
    3690: "Subversion (SVN) - Port 3690",
    50000: "IBM DB2 Database - Port 50000",
    51413: "BitTorrent - Port 51413",
    5500: "VNC Remote Desktop - Port 5500",
    5672: "AMQP (Advanced Message Queuing Protocol) - Port 5672",
    5984: "CouchDB Database - Port 5984",
    6667: "IRC (Alternative Port) - Port 6667",
    8000: "Alternative HTTP Port - Port 8000",
    8081: "Alternative HTTP Port - Port 8081",
    8443: "HTTPS Alternative Port - Port 8443",
    9090: "Alternative HTTP Port - Port 9090"
}