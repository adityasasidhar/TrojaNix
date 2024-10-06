import pefile
import hashlib
import os

# Preload known malware hashes for fast lookup
# (In practice, load from a secure database or file)
MALWARE_HASH_DB = {
    'md5': {"d41d8cd98f00b204e9800998ecf8427e", "5d41402abc4b2a76b9719d911017c592"},
    'sha1': {"da39a3ee5e6b4b0d3255bfef95601890afd80709", "7c211433f02071597741e6ff5a8ea34789abbf43"},
    'sha256': {"e3b0c44298fc1c149afbfb4c8996fb92427ae41e4649b934ca495991b7852b855", "9d5ed678fe57bcca610140957afab571"}
}


# Function to compute file hashes
def compute_hashes(file_path):
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    hash_sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha1.update(chunk)
            hash_sha256.update(chunk)

    return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()


# Function to check hashes against the malware database
def is_malware_by_hash(md5, sha1, sha256):
    return (md5 in MALWARE_HASH_DB['md5']) or (sha1 in MALWARE_HASH_DB['sha1']) or (sha256 in MALWARE_HASH_DB['sha256'])


# Function to extract relevant PE characteristics
def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)
        print(f"Analyzing {file_path}...")

        # Check imports (could be useful to detect malware patterns)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT]
        else:
            imports = []

        # Collect basic PE information
        pe_info = {
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "imports": imports,
            "number_of_sections": pe.FILE_HEADER.NumberOfSections
        }

        return pe_info

    except pefile.PEFormatError:
        print(f"Invalid PE format: {file_path}")
        return None


# Function to efficiently detect malware by both PE analysis and hash comparison
def detect_malware(file_path):
    # Step 1: Hash-based detection
    md5, sha1, sha256 = compute_hashes(file_path)

    if is_malware_by_hash(md5, sha1, sha256):
        return f"File {file_path} is detected as malware based on hash comparison!"

    # Step 2: PE file analysis for further inspection
    pe_info = analyze_pe_file(file_path)

    if pe_info:
        # Additional heuristic checks can be added here based on PE structure anomalies
        if "kernel32.dll" in pe_info['imports']:
            return f"Suspicious file {file_path} imports 'kernel32.dll', often used by malware."

    return f"File {file_path} appears clean or no known malware detected."


# Efficient batch processing for a directory
def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            result = detect_malware(file_path)
            print(result)


# Example usage
if __name__ == "__main__":
    directory_to_scan = "/path/to/scan"
    scan_directory(directory_to_scan)
