# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests",
#     "edgegrid-python",
#     "cryptography",
#     "acme",
#     "josepy",
#     "dnspython"
# ]
# ///

import os
from dotenv import load_dotenv
import sys
import time
import textwrap
import smtplib
import requests
import traceback
import dns.resolver

from urllib.parse import urljoin
from datetime import datetime, timezone
from email.message import EmailMessage

from akamai.edgegrid import EdgeGridAuth, EdgeRc

# ACME & Cryptography Imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from acme import client, messages, challenges
from josepy.jwk import JWKRSA

# This is the magic command that reads the .env file!
load_dotenv()

# ==========================================
# CONFIGURATION
# ==========================================
EDGERC_PATH = os.path.expanduser("~/.edgerc")
EDGERC_SECTION = os.getenv("EDGERC_SECTION")
ACCOUNT_SWITCH_KEY = os.getenv("ACCOUNT_SWITCH_KEY")
CCM_LINEAGE_ID = os.getenv("CCM_LINEAGE_ID")

# ACME Account Details
ACCOUNT_KEY_PATH = os.getenv("ACCOUNT_KEY_PATH")
DIRECTORY_URL = os.getenv("DIRECTORY_URL")
ACCOUNT_URI = os.getenv("ACCOUNT_URI")

# Email Settings
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = 587
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
EMAIL_FROM = SMTP_USER
EMAIL_TO = os.getenv("EMAIL_TO")

# ==========================================
# AKAMAI SESSION SETUP (Unified)
# ==========================================
edgerc = EdgeRc(EDGERC_PATH)
base_url = f"https://{edgerc.get(EDGERC_SECTION, 'host')}"
session = requests.Session()
session.auth = EdgeGridAuth.from_edgerc(edgerc, EDGERC_SECTION)
session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json"
})

if ACCOUNT_SWITCH_KEY:
    session.headers.update({"Account-Switch-Key": ACCOUNT_SWITCH_KEY})

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def send_email(subject, body):
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_FROM
    msg["To"] = EMAIL_TO
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        print(f"✅ Email sent: {subject}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
    finally:
        try:
            server.quit()
        except:
            pass

# ==========================================
# 1. CCM GENERATION & CSR
# ==========================================
def get_ccm_expiration(lineage_id):
    url = f"{base_url}/ccm/v2/lineages/{lineage_id}"
    resp = session.get(url)
    resp.raise_for_status()
    lineage_data = resp.json()
    
    primary_domain = lineage_data.get("subject", {}).get("commonName", str(lineage_id))
    
    gen_id = None
    if "currentProduction" in lineage_data and "productionGenerationId" in lineage_data["currentProduction"]:
        gen_id = lineage_data["currentProduction"]["productionGenerationId"]
    elif "currentStaging" in lineage_data and "stagingGenerationId" in lineage_data["currentStaging"]:
        gen_id = lineage_data["currentStaging"]["stagingGenerationId"]
        
    if not gen_id:
        raise ValueError(f"No active generation found for lineage {lineage_id}")
        
    gen_url = f"{base_url}/ccm/v2/lineages/{lineage_id}/generations/{gen_id}"
    gen_resp = session.get(gen_url)
    gen_resp.raise_for_status()
    
    # --- CORRECTED LIST LOGIC ---
    algorithms = gen_resp.json().get("algorithms", [])
    first_algo = algorithms[0]
    
    not_after_str = first_algo.get("signedCertificateNotValidAfterDate")
    not_after = datetime.fromisoformat(not_after_str.replace("Z", "+00:00"))
    days_left = (not_after - datetime.now(timezone.utc)).days
    
    # Extract the algorithm dynamically from this list item (fallback to ECDSA just in case)
    key_algorithm = first_algo.get("keyAlgorithm", "ECDSA")
    
    # Return it as the 4th item!
    return days_left, gen_id, primary_domain, key_algorithm

def request_new_csr(lineage_id):
    url = f"{base_url}/ccm/v2/lineages/{lineage_id}/generations"
    resp = session.post(url)
    resp.raise_for_status()
    response_data = resp.json()
    head_data = response_data.get("head", {})
    generation_id = head_data.get("headGenerationId")
    
    algorithms = head_data.get("algorithms", [])
    csr_raw = algorithms[0]["csrPem"]
    
    clean_body = csr_raw.replace("-----BEGIN CERTIFICATE REQUEST-----", "") \
                        .replace("-----END CERTIFICATE REQUEST-----", "") \
                        .strip().replace("\n", "").replace("\r", "").replace(" ", "")
    formatted_body = "\n".join(textwrap.wrap(clean_body, 64))
    csr_pem = f"-----BEGIN CERTIFICATE REQUEST-----\n{formatted_body}\n-----END CERTIFICATE REQUEST-----\n"
    
    return generation_id, csr_pem

def get_domains_from_csr(csr_pem):
    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'), default_backend())
    domains = set()
    for ext in csr.extensions:
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            from cryptography.x509 import DNSName
            for name in ext.value.get_values_for_type(DNSName):
                domains.add(name)
    return list(domains), csr

# ==========================================
# 2. DNS LOGIC
# ==========================================
def create_dns_record(record_name, validation, zone):
    endpoint = f'/config-dns/v2/zones/{zone}/recordsets'
    url = f"{base_url}{endpoint}"
    
    payload = {"recordsets": [
        {
        "rdata": [validation],
        "ttl": 60,
        "type": "TXT",
        "name": record_name
        }
    ]}
    result = session.post(url, json=payload)
    result.raise_for_status()
    print(f"✅ DNS TXT record {record_name} created in Akamai EdgeDNS")

def delete_dns_record(record_name, zone):
    # Akamai's standard deletion endpoint for a specific record type
    endpoint = f'/config-dns/v2/zones/{zone}/names/{record_name}/types/TXT'
    url = f"{base_url}{endpoint}"
    
    result = session.delete(url)
    if not result.ok:
        print(f"API Error Response (Delete): {result.text}")
    else:
        print(f"🧹 DNS TXT-record {record_name} cleaned up from Zone {zone}.")

def wait_for_all_dns(pending_validations, timeout=480):
    print("\n⏳ Waiting for DNS propagation for ALL domains simultaneously...")
    start = time.time()
    resolver = dns.resolver.Resolver(configure=False)
    resolver.cache = None
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    remaining = list(pending_validations)
    while remaining:
        for item in list(remaining):
            try:
                answers = resolver.resolve(item['record_name'], "TXT")
                for rdata in answers:
                    txt = rdata.to_text().strip('"')
                    if txt == item['validation']:
                        print(f"  👉 Propagation confirmed for {item['record_name']}")
                        remaining.remove(item)
                        break
            except Exception:
                pass 

        if not remaining:
            print("🚀 All DNS TXT records have successfully propagated!\n")
            return
        if time.time() - start > timeout:
            raise TimeoutError("DNS propagation timed out.")
        time.sleep(10)
    
def promote_certificate(session, base_url, lineage_id, generation_id):
    """Polls Akamai until the certificate is READY_FOR_USE, then promotes it."""
    import time
    
    upload_url = f"{base_url}/ccm/v2/lineages/{lineage_id}/generations/{generation_id}"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    print("\n⏳ Waiting for Akamai to process the certificate (polling status)...")
    ready_for_use = False
    
    # Poll up to 15 times (every 4 seconds = 60 seconds max)
    for attempt in range(15):
        status_resp = session.get(upload_url, headers=headers)
        if status_resp.ok:
            gen_status = status_resp.json().get("generationStatus")
            print(f"   Status check {attempt + 1}/15: {gen_status}")
            if gen_status == "READY_FOR_USE":
                ready_for_use = True
                break
        time.sleep(4)
        
    if not ready_for_use:
        print("⚠️ Warning: Generation did not reach READY_FOR_USE in time. Promotion might fail.")

    print("\n🚀 Promoting certificate to Staging and Production...")
    
    # PAYLOAD FOR PROMOTION
    activation_payload = {
        "operationType": "PROMOTE",
        "generationId": int(generation_id),
        "networks": ["STAGING", "PRODUCTION"]
    }
    
    activation_url = f"{base_url}/ccm/v2/lineages/{lineage_id}/activations"
    activation_response = session.post(activation_url, json=activation_payload, headers=headers)
    
    if not activation_response.ok:
        print(f"API Error Response (Promotion): {activation_response.text}")
        
    activation_response.raise_for_status()
    print("✅ Certificate successfully promoted to Staging and Production!")

# ==========================================
# MAIN WORKFLOW
# ==========================================
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    print(f"Working directory set to: {script_dir}")
    
    try:
        # FIX: Added key_algorithm right here!
        days_left, current_gen_id, primary_domain, key_algorithm = get_ccm_expiration(CCM_LINEAGE_ID)
        
        print(f"Domain: {primary_domain} | Days until expiration: {days_left} | Algorithm: {key_algorithm}")
        
        if days_left > 85:
            print("Certificate is valid for more than 85 days. Exiting.")
            sys.exit(0)

        print("Expiration is under 85 days. Starting renewal process...")
        send_email(f"Let's Encrypt Renewal Started: {primary_domain}", f"Lineage {CCM_LINEAGE_ID} expires in {days_left} days.")

        # 1. GENERATE CSR
        print("Triggering new generation and fetching CSR...")
        new_gen_id, csr_pem = request_new_csr(CCM_LINEAGE_ID)
        domains, csr_obj = get_domains_from_csr(csr_pem)
        print(f"Domains extracted from CSR: {domains}")
        
        # 2. ACME AUTHENTICATION (Using your specific account.key)
        print("Loading Let's Encrypt account key...")
        with open(ACCOUNT_KEY_PATH, "rb") as f:
            account_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        jwk = JWKRSA(key=account_key)
        net = client.ClientNetwork(jwk, user_agent="my-acme-client/1.0")
        directory = client.ClientV2.get_directory(DIRECTORY_URL, net)
        acme_client = client.ClientV2(directory, net)
        
        print("Authenticating with existing Let's Encrypt account...")
        regr = messages.RegistrationResource(
            uri=ACCOUNT_URI,
            body=messages.Registration(key=jwk.public_key())
        )
        # Query the existing registration to attach it to the client
        acme_client.query_registration(regr)

        # 3. CREATE ORDER
        print("Creating Let's Encrypt Order...")
        order = acme_client.new_order(csr_pem.encode('utf-8'))

        # 4. BATCH CREATE DNS CHALLENGES
        pending_dns = []
        challenge_objs = []
        
        print("\n--- BATCHING DNS CHALLENGES ---")
        for authz_url in order.authorizations:
            authz, _ = acme_client.poll(authz_url)
            domain = authz.body.identifier.value
            
            dns_chal = next(c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01))
            validation = dns_chal.validation(jwk)
            record_name = f"_acme-challenge.{domain}"

            zone = '.'.join(domain.split('.')[-2:])
            
            create_dns_record(record_name, validation, zone)
            pending_dns.append({'record_name': record_name, 'validation': validation})
            challenge_objs.append({'chal': dns_chal, 'domain': domain})

        # 5. WAIT ONCE FOR ALL DOMAINS
        wait_for_all_dns(pending_dns)

        # 6. ANSWER CHALLENGES
        print("Submitting challenge responses to Let's Encrypt...")
        for item in challenge_objs:
            acme_client.answer_challenge(item['chal'], item['chal'].response(jwk))

        # 7. FINALIZE ORDER & GET CERTIFICATE
        print("Waiting for Let's Encrypt to validate challenges...")
        finalized_order = acme_client.poll_and_finalize(order)
        
        cert_pem_chain = finalized_order.fullchain_pem
        print("✅ Certificate successfully signed by Let's Encrypt!")

  # 8. UPLOAD TO AKAMAI CCM
        print(f"\nUploading renewed certificate to Generation {new_gen_id}...")
        
        parts = cert_pem_chain.strip().split('-----END CERTIFICATE-----')
        certs = []
        for part in parts:
            if '-----BEGIN CERTIFICATE-----' in part:
                cert_content = (part + '-----END CERTIFICATE-----').strip()
                certs.append(cert_content)
                
        leaf_str = certs[0]
        # Join ALL remaining certificates for the trust chain, not just the first one!
        root_str = "\n".join(certs[1:]) if len(certs) > 1 else ""

        # Safety check: Force the algorithm to strict uppercase just in case
        safe_algo = str(key_algorithm).strip().upper()
        if safe_algo not in ["RSA", "ECDSA"]:
            print(f"Warning: Unexpected algorithm '{safe_algo}' found. Defaulting to 'ECDSA'.")
            safe_algo = "ECDSA"

        # THE FINAL DYNAMIC PAYLOAD
        payload2 = {
            "algorithms": {
                safe_algo: {
                    "signedCertificatePem": leaf_str,
                    "trustChainPem": root_str
                }
            }
        }
        
        upload_endpoint = f"/ccm/v2/lineages/{CCM_LINEAGE_ID}/generations/{new_gen_id}"
        upload_url = f"{base_url}{upload_endpoint}"
        
        # WE ARE GOING WITH THE DOCS: Standard JSON headers!
        upload_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        #print(f"Payload being sent (first 200 chars): {json.dumps(payload2)[:200]}...")
        print(f"Payload being sent (first 200 chars): {str(payload2)[:200]}...")

        # Include the headers in the patch request
        result2 = session.patch(upload_url, json=payload2, headers=upload_headers)
        
        if not result2.ok:
            print(f"API Error Response (CCM Upload): {result2.text}")
            
        result2.raise_for_status()
        print(f"✅ {safe_algo} Certificate successfully uploaded and activated in Akamai CCM.")

        # ==========================================
        # 9. TRIGGER THE PROMOTION
        # ==========================================
        promote_certificate(session, base_url, CCM_LINEAGE_ID, new_gen_id)
        
        send_email(f"SUCCESS: Let's Encrypt Renewal for {primary_domain}", "Certificate renewed and uploaded to Akamai CCM.")
        
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"\n❌ ERROR:\n{error_details}")
        send_email(f"FAILED: Let's Encrypt Renewal for {CCM_LINEAGE_ID}", f"Error:\n{error_details}")
        sys.exit(1)
        
    finally:
        # CLEANUP BATCH
        if 'pending_dns' in locals():
            print("\n--- CLEANING UP DNS RECORDS ---")
            for item in pending_dns:
                try:
                    # FIX: Extract the zone directly from the record name before deleting
                    zone = '.'.join(item['record_name'].split('.')[-2:])
                    delete_dns_record(item['record_name'], zone)
                except Exception as e:
                    print(f"Warning: could not clean up {item['record_name']}: {e}")

if __name__ == "__main__":
    main()
