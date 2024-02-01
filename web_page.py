import streamlit as st
from PIL import Image
import re
import pandas as pd
from tld import get_tld
import tldextract

import dns.resolver
import pickle as pkl
import socket
import urlopen
import urllib
import whois
from urllib.parse import urlparse
import requests

import dns.resolver
import folium
from streamlit_folium import folium_static
from streamlit import session_state as ss 
import hashlib
from datetime import datetime
import OpenSSL,ssl
import concurrent.futures

def get_domain(url):
    parser = urlparse(url)
    if parser.netloc == 'bit.ly':
        try:
            url = urlopen(url).geturl()
            parser = urlparse(url)
            parts = parser.netloc.split(".")
            if len(parts) > 2:
                subdomain = parts[0]
                root_domain = ".".join(parts[1:])
                return root_domain
            elif len(parts) == 2:
                subdomain = None
                root_domain = ".".join(parts)
                return root_domain
            else:
                return parser.netloc
        except urllib.error.HTTPError as e:
            return 0
        except urllib.error.URLError as e:
            return 0
    parts = parser.netloc.split(".")
    if len(parts) > 2:
        subdomain = parts[0]
        root_domain = ".".join(parts[1:])
        return root_domain
    elif len(parts) == 2:
        subdomain = None
        root_domain = ".".join(parts)
        return root_domain
    else:
        return parser.netloc
def whois_lookup(domain):
    whois_server = "whois.iana.org"
    port = 43

    # Connect to the WHOIS server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((whois_server, port))

        # Send the domain query
        s.sendall(f"{domain}\r\n".encode())

        # Receive and store the response
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data

    return response.decode()

def get_geolocation(ip_address, api_key):
    url = f"https://ipinfo.io/{ip_address}/json?token={api_key}"

    try:
        response = requests.get(url)
        data = response.json()

        if 'loc' in data:
            latitude, longitude = data['loc'].split(',')
            return {
                'latitude': float(latitude),
                'longitude': float(longitude)
            }
        else:
            return None

    except requests.exceptions.RequestException as e:
        print(f"Error fetching data: {e}")
        return None



def extract_whois_data(whois_response):
    lines = whois_response.splitlines()
    relevant_info = {}

    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in ['domain', 'organisation', 'address', 'whois', 'status', 'remarks', 'created', 'changed', 'source']:
                relevant_info[key.capitalize()] = value

    return relevant_info

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0

# df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

# df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))


def count_dot(url):
    return url.count('.')

# df['count.'] = df['url'].apply(lambda i: count_dot(i))

def count_www(url):
    return url.count('www')

# df['count-www'] = df['url'].apply(lambda i: count_www(i))

def count_atrate(url):
    return url.count('@')

# df['count@'] = df['url'].apply(lambda i: count_atrate(i))

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

# df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

# df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))

def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0

# df['short_url'] = df['url'].apply(lambda i: shortening_service(i))

def count_https(url):
    return url.count('https')

# df['count-https'] = df['url'].apply(lambda i: count_https(i))

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        return 1
    else:
        return 0

# df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))

def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits

# df['count-digits']= df['url'].apply(lambda i: digit_count(i))

def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

# df['count-letters']= df['url'].apply(lambda i: letter_count(i))

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

# df['fd_length'] = df['url'].apply(lambda i: fd_length(i))

def get_tld(url):
    try:
        return tldextract.extract(url).suffix
    except:
        return None
# df['tld']=df['url'].apply(lambda i: get_tld(i))
# Function to get the length of the top-level domain (TLD)
def tld_length(tld):
    return len(tld) if pd.notnull(tld) else -1

# df['tld_length'] = df['tld'].apply(lambda i: len(i))

def performwhois(url):
    try:
        result = whois.whois(url)
        return 1 #success
    except Exception:
        return 0

def extract_pri_domain(url):
    try:
        parsed_url = urlparse(url)
        pri_domain = parsed_url.netloc
        filter = r"(?:www\.)?([\w\-]+\.[\w\-]{2,})"
        match = re.search(filter, pri_domain)

        if match:
          pri_domain = match.group(1)
    except :
        pri_domain= 0
    return pri_domain

def get_NS_record(domain):
    #domain = get_domain(url)
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return 1

    except dns.resolver.NXDOMAIN as e:
        return 0
    except dns.resolver.NoAnswer as e:
        return 0
    except dns.resolver.Timeout as e:
        return 0
    except Exception as e:
        return 0


def get_MX_record(domain):
    #domain = get_domain(url)
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return 1

    except dns.resolver.NXDOMAIN as e:
        return 0
    except dns.resolver.NoAnswer as e:
        return 0
    except dns.resolver.Timeout as e:
        return 0
    except Exception as e:
        return 0


def get_aaaa_record(url):
     try:
        answers = dns.resolver.resolve(url, 'AAAA')
        return 1
     except dns.exception.Timeout:
        return 0
     except dns.resolver.NoNameservers:
        return 0
     except dns.resolver.NXDOMAIN:
        return 0
     except dns.resolver.NoAnswer:
        return 0

def get_a_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return 1
    except dns.exception.Timeout:
        return 0
    except dns.resolver.NoNameservers:
        return 0
    except dns.resolver.NXDOMAIN:
        return 0
    except dns.resolver.NoAnswer:
        return 0

#dnssec certificate verification
def verify_dnssec(domain):
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.use_edns(0, dns.flags.DO | dns.flags.AD | dns.flags.CD)
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']

        dnskeys = resolver.resolve(domain, dns.rdatatype.DNSKEY)
        if dnskeys.response.rcode() == dns.rcode.NOERROR:
            return 1  # DNSSEC validation passed
        else:
            return -1  # DNSSEC validation failed

    except dns.resolver.NXDOMAIN:
        return 0  # Domain not found
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return 0  # No DNSKEY records or nameservers found

    except Exception:
        return 0  # Other errors

def get_url_region(primary_domain):
    ccTLD_to_region = {
    ".ac": "Ascension Island",    ".ad": "Andorra",    ".ae": "United Arab Emirates",    ".af": "Afghanistan",    ".ag": "Antigua and Barbuda",    ".ai": "Anguilla",
    ".al": "Albania",    ".am": "Armenia",    ".an": "Netherlands Antilles",    ".ao": "Angola",    ".aq": "Antarctica",    ".ar": "Argentina",
    ".as": "American Samoa",    ".at": "Austria",    ".au": "Australia",    ".aw": "Aruba",    ".ax": "Åland Islands",    ".az": "Azerbaijan",
    ".ba": "Bosnia and Herzegovina",    ".bb": "Barbados",    ".bd": "Bangladesh",    ".be": "Belgium",    ".bf": "Burkina Faso",    ".bg": "Bulgaria",
    ".bh": "Bahrain",    ".bi": "Burundi",    ".bj": "Benin",    ".bm": "Bermuda",    ".bn": "Brunei Darussalam",    ".bo": "Bolivia",
    ".br": "Brazil",    ".bs": "Bahamas",    ".bt": "Bhutan",    ".bv": "Bouvet Island",    ".bw": "Botswana",    ".by": "Belarus",
    ".bz": "Belize",    ".ca": "Canada",    ".cc": "Cocos Islands",    ".cd": "Democratic Republic of the Congo",    ".cf": "Central African Republic",    ".cg": "Republic of the Congo",
    ".ch": "Switzerland",    ".ci": "Côte d'Ivoire",    ".ck": "Cook Islands",    ".cl": "Chile",    ".cm": "Cameroon",    ".cn": "China",
    ".co": "Colombia",    ".cr": "Costa Rica",    ".cu": "Cuba",    ".cv": "Cape Verde",    ".cw": "Curaçao",    ".cx": "Christmas Island",
    ".cy": "Cyprus",    ".cz": "Czech Republic",    ".de": "Germany",    ".dj": "Djibouti",    ".dk": "Denmark",    ".dm": "Dominica",
    ".do": "Dominican Republic",    ".dz": "Algeria",    ".ec": "Ecuador",    ".ee": "Estonia",    ".eg": "Egypt",    ".er": "Eritrea",
    ".es": "Spain",    ".et": "Ethiopia",    ".eu": "European Union",    ".fi": "Finland",    ".fj": "Fiji",    ".fk": "Falkland Islands",
    ".fm": "Federated States of Micronesia",    ".fo": "Faroe Islands",    ".fr": "France",    ".ga": "Gabon",    ".gb": "United Kingdom",    ".gd": "Grenada",
    ".ge": "Georgia",    ".gf": "French Guiana",    ".gg": "Guernsey",    ".gh": "Ghana",    ".gi": "Gibraltar",    ".gl": "Greenland",
    ".gm": "Gambia",    ".gn": "Guinea",    ".gp": "Guadeloupe",    ".gq": "Equatorial Guinea",    ".gr": "Greece",    ".gs": "South Georgia and the South Sandwich Islands",
    ".gt": "Guatemala",    ".gu": "Guam",    ".gw": "Guinea-Bissau",    ".gy": "Guyana",    ".hk": "Hong Kong",    ".hm": "Heard Island and McDonald Islands",
    ".hn": "Honduras",    ".hr": "Croatia",    ".ht": "Haiti",    ".hu": "Hungary",    ".id": "Indonesia",    ".ie": "Ireland",
    ".il": "Israel",    ".im": "Isle of Man",    ".in": "India",    ".io": "British Indian Ocean Territory",    ".iq": "Iraq",    ".ir": "Iran",
    ".is": "Iceland",    ".it": "Italy",    ".je": "Jersey",    ".jm": "Jamaica",    ".jo": "Jordan",    ".jp": "Japan",
    ".ke": "Kenya",    ".kg": "Kyrgyzstan",    ".kh": "Cambodia",    ".ki": "Kiribati",    ".km": "Comoros",    ".kn": "Saint Kitts and Nevis",
    ".kp": "Democratic People's Republic of Korea (North Korea)",    ".kr": "Republic of Korea (South Korea)",    ".kw": "Kuwait",    ".ky": "Cayman Islands",    ".kz": "Kazakhstan",    ".la": "Laos",
    ".lb": "Lebanon",    ".lc": "Saint Lucia",    ".li": "Liechtenstein",    ".lk": "Sri Lanka",    ".lr": "Liberia",    ".ls": "Lesotho",
    ".lt": "Lithuania",    ".lu": "Luxembourg",    ".lv": "Latvia",    ".ly": "Libya",    ".ma": "Morocco",    ".mc": "Monaco",
    ".md": "Moldova",    ".me": "Montenegro",    ".mf": "Saint Martin (French part)",    ".mg": "Madagascar",    ".mh": "Marshall Islands",    ".mk": "North Macedonia",
    ".ml": "Mali",    ".mm": "Myanmar",    ".mn": "Mongolia",    ".mo": "Macao",    ".mp": "Northern Mariana Islands",    ".mq": "Martinique",
    ".mr": "Mauritania",    ".ms": "Montserrat",    ".mt": "Malta",    ".mu": "Mauritius",    ".mv": "Maldives",    ".mw": "Malawi",
    ".mx": "Mexico",    ".my": "Malaysia",    ".mz": "Mozambique",    ".na": "Namibia",    ".nc": "New Caledonia",    ".ne": "Niger",
    ".nf": "Norfolk Island",    ".ng": "Nigeria",    ".ni": "Nicaragua",    ".nl": "Netherlands",    ".no": "Norway",    ".np": "Nepal",
    ".nr": "Nauru",    ".nu": "Niue",    ".nz": "New Zealand",    ".om": "Oman",    ".pa": "Panama",    ".pe": "Peru",
    ".pf": "French Polynesia",    ".pg": "Papua New Guinea",    ".ph": "Philippines",    ".pk": "Pakistan",    ".pl": "Poland",    ".pm": "Saint Pierre and Miquelon",
    ".pn": "Pitcairn",    ".pr": "Puerto Rico",    ".ps": "Palestinian Territory",    ".pt": "Portugal",    ".pw": "Palau",    ".py": "Paraguay",
    ".qa": "Qatar",    ".re": "Réunion",    ".ro": "Romania",    ".rs": "Serbia",    ".ru": "Russia",    ".rw": "Rwanda",
    ".sa": "Saudi Arabia",    ".sb": "Solomon Islands",    ".sc": "Seychelles",    ".sd": "Sudan",    ".se": "Sweden",    ".sg": "Singapore",
    ".sh": "Saint Helena",    ".si": "Slovenia",    ".sj": "Svalbard and Jan Mayen",    ".sk": "Slovakia",    ".sl": "Sierra Leone",    ".sm": "San Marino",
    ".sn": "Senegal",    ".so": "Somalia",    ".sr": "Suriname",    ".ss": "South Sudan",    ".st": "São Tomé and Príncipe",    ".sv": "El Salvador",
    ".sx": "Sint Maarten (Dutch part)",    ".sy": "Syria",    ".sz": "Eswatini",    ".tc": "Turks and Caicos Islands",    ".td": "Chad",    ".tf": "French Southern Territories",
    ".tg": "Togo",    ".th": "Thailand",    ".tj": "Tajikistan",    ".tk": "Tokelau",    ".tl": "Timor-Leste",    ".tm": "Turkmenistan",
    ".tn": "Tunisia",    ".to": "Tonga",    ".tr": "Turkey",    ".tt": "Trinidad and Tobago",    ".tv": "Tuvalu",    ".tw": "Taiwan",
    ".tz": "Tanzania",    ".ua": "Ukraine",    ".ug": "Uganda",    ".uk": "United Kingdom",    ".us": "United States",    ".uy": "Uruguay",
    ".uz": "Uzbekistan",    ".va": "Vatican City",    ".vc": "Saint Vincent and the Grenadines",    ".ve": "Venezuela",    ".vg": "British Virgin Islands",    ".vi": "U.S. Virgin Islands",
    ".vn": "Vietnam",    ".vu": "Vanuatu",    ".wf": "Wallis and Futuna",    ".ws": "Samoa",    ".ye": "Yemen",    ".yt": "Mayotte",
    ".za": "South Africa",    ".zm": "Zambia",    ".zw": "Zimbabwe"
    }
    for ccTLD in ccTLD_to_region:
        if primary_domain.endswith(ccTLD):
            return ccTLD_to_region[ccTLD]

    return "Global"

def get_domain_x(url):
    # Extract the domain from the URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain

valid = True

def fetch_certificate(url):
    domain = get_domain_x(url)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)  # Set a timeout value of 5 seconds
            try:
                s.connect((domain, 443))
            except (ConnectionRefusedError, OSError):
                return -1
            cert = s.getpeercert()
        return cert
    except (ssl.SSLError, socket.gaierror, socket.timeout, ConnectionResetError, FileNotFoundError, OSError) as e:
        return -1
    except ValueError as ve:
        if "check_hostname requires server_hostname" in str(ve):
            return -2  # This code indicates the specific error case
        else:
            raise

def is_valid_certificate(url):
    try:
        cert = fetch_certificate(url)
        if cert == -1 or cert == -2:
            return -1
        return 1
    except:
        return -1

def is_recently_issued(url):
    try:
        cert = fetch_certificate(url)
        if cert == -1 or cert==-2:
            return -1
        cert_issue_date = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        ten_days_ago = datetime.now() - timedelta(days=10)
        if cert_issue_date > ten_days_ago:
            return 1
        else:
            return 0
    except:
        return -1

def is_trusted_issuer(url):
    try:
        cert = fetch_certificate(url)
        if cert == -1 or cert ==-2:
            valid = False
            return -1
        issuer = dict(x[0] for x in cert['issuer'])
        issuer_cn = issuer.get('commonName', '')
        trusted_CAs = ["DigiCert", "GlobalSign", "Comodo", "Symantec", "Thawte", "R3", "GoDaddy", "Network Solutions", "GTS CA", "Cloudflare Inc ECC"]
        if any(issuer_cn.startswith(ca) for ca in trusted_CAs):
            return 1
        else:
            return 0
    except:
        return -1

def extract_root_domain(url):
    extracted = tldextract.extract(url)
    root_domain = extracted.domain
    return root_domain

def hash_encode(category):
    hash_object = hashlib.md5(category.encode())
    return int(hash_object.hexdigest(),16)%(10**8)

def get_ssl_certificate(url):
    try:
        hostname = url.replace("https://", "").replace("http://", "")
        cert = ssl.get_server_certificate((hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        certificate = {
            'subject': dict(x509.get_subject().get_components()),
            'issuer': dict(x509.get_issuer().get_components()),
            'notBefore': x509.get_notBefore().decode('utf-8'),
            'notAfter': x509.get_notAfter().decode('utf-8'),
        }
        return certificate
    except Exception as e:
        return None

def dateproper(datee):
    datee = datetime.strptime(str(datee), "%Y%m%d%H%M%S%z")
    datee = datee.strftime("%Y-%m-%d %H:%M:%S")
    return datee

def is_phishing_website(url):
    certificate = get_ssl_certificate(url)
    SSL_Certificate_Information = {}
    if certificate:
        SSL_Certificate_Information["Common Name (CN)"] = certificate['subject'][b'CN'].decode('utf-8')
        SSL_Certificate_Information["Issuer"] = certificate['issuer'][b'CN'].decode('utf-8')
        SSL_Certificate_Information["Valid From"] = dateproper(certificate['notBefore'])
        SSL_Certificate_Information["Valid Until"] = dateproper(certificate['notAfter'])
    return SSL_Certificate_Information


def extract_subdomain_and_root_domain(url):
    # Parse the URL to get its components
    parsed_url = urlparse(url)
    
    # Extract the netloc part (which contains the subdomain and root domain)
    netloc = parsed_url.netloc
    
    # Split the netloc by dots to get the subdomain and root domain
    parts = netloc.split(".")
    if len(parts) > 2:
        subdomain = parts[0]
        root_domain = ".".join(parts[1:])
        return netloc, subdomain, root_domain
    elif len(parts) == 2:
        subdomain = None
        root_domain = ".".join(parts)
        return netloc, subdomain, root_domain
    else:
        return None, None, None

dns_store={}

def get_dns_records(url):  # sourcery skip: identity-comprehension
    domain, subdomain, root_domain = extract_subdomain_and_root_domain(url)
    li1 = ['A', 'AAAA', 'CNAME']
    #A, AAAA, CNAME records (use domain name)
    for i in li1:
        try:
            answers = dns.resolver.resolve(domain, i)
            dns_store[i] = [rdata for rdata in answers]

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
            # None
            dns_store[i] = None

    #NS, MX (use root domain)
    li2 = ['NS', 'MX']
    for i in li2:
        try:
            records = dns.resolver.resolve(root_domain, i)
            dns_store[i] = [record.to_text() for record in records]
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
            dns_store[i] = None
            
    # TXT Record
    try:
        answers= dns.resolver.resolve(root_domain, 'TXT')
        dns_store['TXT'] = [rdata for rdata in answers]
    
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
        dns_store[i] = None
 
    #CAA Records
    try:
        answers = dns.resolver.resolve(root_domain, 'CAA')
        dns_store['CAA'] = [rdata for rdata in answers]
            
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception) as e:
        dns_store[i] = None
    
    return dns_store


def feature_extraction(df):
  #try
  df['domain'] = df['url'].apply(lambda i: get_domain(i))
  df['A'] = df['domain'].apply(lambda x: get_a_record(x))
  df['AAAA'] = df['domain'].apply(lambda x: get_aaaa_record(x))
  df['NS'] = df['domain'].apply(lambda x: get_NS_record(x))
  df['MX'] = df['domain'].apply(lambda x: get_MX_record(x))
  df['DNSSEC Validation'] = df['domain'].apply(lambda x: verify_dnssec(x))

  df['use_of_ip'] = df['url'].apply(lambda i: having_ip_address(i))
  df['abnormal_url'] = df['url'].apply(lambda i: abnormal_url(i))
  df['count.'] = df['url'].apply(lambda i: count_dot(i))
  df['count-www'] = df['url'].apply(lambda i: count_www(i))
  df['count@'] = df['url'].apply(lambda i: count_atrate(i))
  df['count_dir'] = df['url'].apply(lambda i: no_of_dir(i))
  df['count_embed_domian'] = df['url'].apply(lambda i: no_of_embed(i))
  df['short_url'] = df['url'].apply(lambda i: shortening_service(i))
  df['count-https'] = df['url'].apply(lambda i: count_https(i))
  df['sus_url'] = df['url'].apply(lambda i: suspicious_words(i))
  df['count-digits']= df['url'].apply(lambda i: digit_count(i))
  df['count-letters']= df['url'].apply(lambda i: letter_count(i))
  df['fd_length'] = df['url'].apply(lambda i: fd_length(i))
  df['tld']=df['url'].apply(lambda i: get_tld(i))
  df['tld_length'] = df['tld'].apply(lambda i: len(i))
  #df["count-https"] = df["url"].apply(lambda i: i.count("https"))
  df["count-http"] = df["url"].apply(lambda i: i.count("http"))
  df["count%"] = df["url"].apply(lambda i: i.count("%"))
  df["count?"] = df["url"].apply(lambda i: i.count("?"))
  df["count-"] = df["url"].apply(lambda i: i.count("-"))
  df["count="] = df["url"].apply(lambda i: i.count("="))
  df["url_length"] = df["url"].apply(lambda i: len(str(i)))
  df["hostname_length"] = df["url"].apply(lambda i: len(urlparse(i).netloc))

  df['pri_domain'] = df['url'].apply(lambda x: extract_pri_domain(x))
  df['url_region'] = df['pri_domain'].apply(lambda x: get_url_region(str(x)))
  df['root_domain'] = df['pri_domain'].apply(lambda x: extract_root_domain(str(x)))
# Apply hash encoding to the categorical feature
  df['root_domain'] = df['root_domain'].apply(hash_encode)
  df['url_region'] = df['url_region'].apply(hash_encode)

  df['whois_verified'] = df['url'].apply(lambda x: performwhois(x))

  df['cert'] = df['pri_domain'].apply(lambda i: fetch_certificate(i))
  #df['cert'] = df['cert'].apply(lambda x: x[1] if x[0] is None else None)

  df['valid_cert'] = df['cert'].apply(lambda i: is_valid_certificate(i))
  df['recent_issue'] = df['cert'].apply(lambda i: is_recently_issued(i))
  df['trusted_issue'] = df['cert'].apply(lambda i: is_trusted_issuer(i))

  df = df[['A', 'AAAA', 'NS', 'MX', 'DNSSEC Validation',
       'valid_cert', 'recent_issue', 'trusted_issue', 'use_of_ip',
       'abnormal_url', 'count.', 'count-www', 'count@', 'count_dir',
       'count_embed_domian', 'short_url', 'count-https', 'sus_url',
       'count-digits', 'count-letters', 'fd_length', 'tld_length',
       'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
       'hostname_length', 'url_region', 'root_domain', 'whois_verified']]

  return df

# Function to check if the URL is legitimate or phishing
def check_phishing(df):
    if df.empty:
        return "Error: Please enter a valid URL."
    model = pkl.load(open("best_model_final.pkl", "rb"))
    df = feature_extraction(df)
    le = pkl.load(open("linear.pkl", "rb"))
    value = le.inverse_transform(model.predict(df))
    return value

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

def main():
    st.set_page_config(page_title="Phishing URL Detector", page_icon="🕵️‍♂️")
    
    # Custom CSS for styling
    st.markdown("""
    <style>
    body {
        color: #333333;
        background-color: #f5f5f5;
    }
    .stTextInput input {
        background-color: #ffffff;
        color: #333333;
    }
    .logo {
        position: absolute;
        top: 20px;
        right: 20px;
        max-width: 10px;
    }
    .result-badge {
        display: inline-block;
        padding: 5px 10px;
        font-size: 18px;
        border-radius: 8px;
        text-align: center;
    }
    .legitimate {
        background-color: #2ecc71;
        color: white;
        animation: balloon-run 1s infinite;
    }
    .phishing {
        background-color: #e74c3c;
        color: white;
        animation: warning 0.5s infinite;
    }

    @keyframes balloon-run {
        0% { transform: translateY(0); }
        50% { transform: translateY(-10px); }
        100% { transform: translateY(0); }
    }

    @keyframes warning {
        0% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        75% { transform: translateX(5px); }
        100% { transform: translateX(0); }
    }

    .stCheckbox > div > label {
        border: 1px solid #3f8abf;
        background-color: #3f8abf;
        color: white;
        padding: 8px 16px;
        border-radius: 5px;
        cursor: pointer;
    }
    .stCheckbox > div > label > span {
        display: none;
    }
    .stCheckbox > div > input:checked + label {
        background-color: #f7f7f7;
        color: #3f8abf;
    }   
    </style>
    """, unsafe_allow_html=True)
    flag=True
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
    # Logo
    logo_image = Image.open("logo.png")
    logo_image_resized = logo_image.resize((150, 150))
    st.image(logo_image_resized, use_column_width=False, caption="Logo",width=100)
    
    st.title("Phishing URL Detector")
    st.write("Enter a URL to check if it's legitimate or phishing.")

    # User input: URL
    user_input = st.text_input("Enter URL here:","")
    if (len(user_input)>0) and ("https://" not in user_input and "http://" not in user_input) :
        flag=False
        st.warning("Please enter the full URL including the 'https://' or 'http://' protocol.")
    domain_name = get_domain_x(user_input)
    if flag:
        is_trusted_issuer(user_input) #to check the validity of the url
        # print(valid) 

        if 'button_1' not in ss:
            ss.button_1 = 0
        if 'button_2' not in ss:
            ss.button_2 = 0

        def count(key):
            ss[key] += 1
        st.button("Check",on_click=count, args=('button_1',))
        check = bool(ss.button_1 % 2)
        if check:
            if user_input:
                # Call the check_phishing function
                df = pd.DataFrame({'url': [user_input]})
                result = check_phishing(df)

                # Determine result message and set the flag to show result
                if result == "legitimate":
                    st.markdown("<div class='result-badge legitimate'>✅ Legitimate</div>", unsafe_allow_html=True)
                    st.markdown("<div class='balloon-run'>🎈🎈🎈</div>", unsafe_allow_html=True)
                    st.markdown("<style>body{background-color: #ddffdd;}</style>", unsafe_allow_html=True)
                else:
                    st.markdown("<div class='result-badge phishing'>⚠️ Phishing</div>", unsafe_allow_html=True)
                    st.markdown("<div class='warning'>⚠️⚠️⚠️</div>", unsafe_allow_html=True)

            else:
                st.warning("Please enter a URL.")

            whois_response = whois_lookup(domain_name)
            relevant_info = extract_whois_data(whois_response)

            response = is_phishing_website(user_input)

            data = get_dns_records(user_input)
            flattened_data = []
            for key, value in data.items():
                if value != None and value != [] and value != '':
                    if isinstance(value, list) :
                        flattened_data.extend([(key, item) for item in value])
                    else:
                        flattened_data.append((key, value))


            st.button("Show Information",on_click=count, args=('button_2',))
            show_info= bool(ss.button_2 % 2)
            if show_info:
                if relevant_info:
                    whois_df = pd.DataFrame(relevant_info.items(), columns=['Property', 'Value'])
                    st.write("Whois Lookup:")
                    st.table(whois_df)

                if response:
                    ssl_response = pd.DataFrame(response.items(), columns=['Property', 'Value'])
                    st.write("SSL Lookup:")
                    st.table(ssl_response)

                if flattened_data:
                    dns_response = pd.DataFrame(flattened_data, columns=['Type', 'Value'])
                    st.write("DNS Lookup:")
                    st.table(dns_response)

                st.write("Port Scan")
                ports_search = st.multiselect("Select ports to scan", list(port_services.values()), default=["HTTP (Hypertext Transfer Protocol) - Port 80","HTTPS (HTTP Secure) - Port 443"])
                ports_search =  [ int(x.split(" - Port ")[1]) for x in ports_search]
                if st.button("Scan"):
                    parsed_url = urlparse(user_input)
                    host_name = parsed_url.hostname
                    open_ports = scan_ports(host_name, ports_search)
                    open_ports = [port_services[port] for port in open_ports]
                    open_ports = pd.DataFrame(open_ports, columns=['Open Ports'])
                    st.write("<h4 style='color: white;'>List of Open Ports:</h4>", unsafe_allow_html=True)
                    # for port in open_ports:
                    #     st.write(f"<p style='margin: 0;'>{port}</p>", unsafe_allow_html=True)
                    st.table(open_ports)

                st.write("\n")                                    
                api_key = 'a0129d87df217a'
                if user_input:
                    try:
                        ipv4_records = dns.resolver.resolve(domain_name, 'A')
                        addresses = [record.address for record in ipv4_records]

                        location_data = []
                        for ip_address in addresses:
                            result = get_geolocation(ip_address, api_key)
                            if result:
                                latitude = result['latitude']
                                longitude = result['longitude']
                                if latitude and longitude:  # Check if latitude and longitude are available
                                    location_data.append((latitude, longitude))

                        if location_data:
                            st.write("Geolocation data:")
                            map = folium.Map(location=[location_data[0][0], location_data[0][1]], zoom_start=6)
                            for lat, lon in location_data:
                                folium.Marker(location=[lat, lon], tooltip="Location").add_to(map)

                            folium_static(map)
                        else:
                            st.write("No valid geolocation data available for the given domains.")

                    except dns.resolver.NXDOMAIN:
                        st.write(f"Domain '{user_input}' does not exist.")
                    except dns.resolver.NoAnswer:
                        st.write(f"No DNS records found for '{user_input}'.")
                    except dns.exception.DNSException as e:
                        st.write(f"Error resolving domain '{user_input}': {e}")
                        
                        
if __name__ == "__main__":
    main()
