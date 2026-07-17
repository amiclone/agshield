import os
import sys
import random
import string

def get_random_string(length=12):
    letters = string.ascii_lowercase + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def secure_wipe(filepath, passes=1):
    """
    Securely wipes a file by:
    1. Overwriting content with random bytes.
    2. Renaming to a random string (to hide name in MFT/Journal).
    3. Deleting the file.
    """
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return False
    
    try:
        filesize = os.path.getsize(filepath)
        
        with open(filepath, "wb") as f:
            for i in range(passes):
                # We could do specific patterns, but random is fine for simulation
                # Using os.urandom is cryptographically secure but slower. 
                # For large files, this loop needs to be chunked.
                
                # Chunked write
                remaining = filesize
                chunk_size = 1024 * 1024 # 1MB
                
                while remaining > 0:
                    write_len = min(remaining, chunk_size)
                    f.write(os.urandom(write_len))
                    remaining -= write_len
                    
                f.flush()
                # Reset ptr for next pass (if any)
                f.seek(0)
                print(f"[*] Pass {i+1} complete for {filepath}")

        # Rename
        dir_name = os.path.dirname(filepath)
        new_name = os.path.join(dir_name, get_random_string())
        os.rename(filepath, new_name)
        print(f"[*] Renamed file to {new_name}")
        
        # Delete
        os.remove(new_name)
        print(f"[+] Securely deleted {filepath}")
        return True
        
    except Exception as e:
        print(f"[-] Wiper failed on {filepath}: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python data_wiper.py <file_path> [passes]")
        sys.exit(1)
        
    target = sys.argv[1]
    passes_arg = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    secure_wipe(target, passes_arg)
