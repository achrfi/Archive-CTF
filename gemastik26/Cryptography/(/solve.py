import hashlib
import json

def solve():
    # Load the challenge data
    with open("output.sad", "r") as f:
        data = json.load(f)
        
    salt = data["salt"].encode()
    alphabet = data["alphabet"]
    checkpoints = data["checkpoints"]
    
    # Initialize the base state exactly as sad.py does
    state = hashlib.sha256(salt).digest()
    flag = ""
    
    print("[*] Starting hash chain reversal...")
    
    # Brute-force each character one by one
    for i, target_hex in enumerate(checkpoints):
        found = False
        
        for char in alphabet:
            # Test the current character against the previous state
            test_state = hashlib.sha256(state + char.encode() + salt).digest()
            
            # If the resulting hex matches the checkpoint, we found the correct character
            if test_state.hex() == target_hex:
                flag += char
                state = test_state
                found = True
                print(f"[*] Recovered {i+1}/{len(checkpoints)}: {flag}")
                break
                
        if not found:
            print(f"[-] Failed to find character at index {i}")
            return
            
    print(f"\n[+] Final Flag: {flag}")

if __name__ == "__main__":
    solve()
