def settler():
    def calculate_sha256(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    """
    so basically what this guy will do is store a hash and location of every file on this pc, 
    so when the next time you deep scan or stuff, it simply refernces all that it is and checks for any irregularities
    if they are found, it will take a closer look and scan it for any malicious intent, if it is clear then it will simply 
    add that file to its database and location for the next scan, reguularly updating itself and I'm also making 
    the file completely immutable so that a malware doesnt just register itself to escape detection. 
    
    I kinda like the sound of it tbh
    
    """