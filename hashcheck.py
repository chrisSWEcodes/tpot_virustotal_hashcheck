import os
import json
import hashlib
import requests
import logging
from datetime import datetime
import tarfile

# Load configuration
with open("config.json", "r") as config_file:
    config = json.load(config_file)

API_KEY = config["virustotal_api_key"]
SCAN_DIR = config["scan_directory"]
EXCLUDE_DIRS = [os.path.abspath(d) for d in config["exclude_directories"]]
LOG_DIR = config["log_directory"]
ENABLE_CHECK = config["enable_virustotal_check"]
VERBOSE = config["verbose_logging"]
TELEGRAM_SETTINGS = config["telegram_settings"]  # Telegram bot settings

PROCESSED_HASHES_FILE = os.path.join(LOG_DIR, "processed_hashes.log")
NEW_HASHES_FILE = os.path.join(LOG_DIR, "new_hashes.log")
ARCHIVE_HISTORY_FILE = os.path.join(LOG_DIR, "archive_history.log")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Setup logging
logging.basicConfig(
    filename=os.path.join(LOG_DIR, "activity.log"),
    level=logging.DEBUG if VERBOSE else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def format_file_size(size_bytes):
    """Convert file size to human-readable format with units."""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.2f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"

def calculate_checksum(file_path):
    """Calculate the checksum of a file using SHA256."""
    hash_func = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating checksum for {file_path}: {e}")
        return None

def load_processed_hashes():
    """Load previously processed hashes into a set."""
    processed_hashes = set()
    if os.path.exists(PROCESSED_HASHES_FILE):
        with open(PROCESSED_HASHES_FILE, "r") as file:
            for line in file:
                parts = line.strip().split(";")
                if len(parts) > 1:  # Assuming second column is the hash
                    processed_hashes.add(parts[1])
    return processed_hashes

def load_archive_history():
    """Load archive history into a dictionary."""
    archive_history = {}
    if os.path.exists(ARCHIVE_HISTORY_FILE):
        with open(ARCHIVE_HISTORY_FILE, "r") as file:
            for line in file:
                parts = line.strip().split(";")
                if len(parts) == 2:  # Assuming format: path;checksum
                    archive_history[parts[0]] = parts[1]
    return archive_history

def save_archive_history(archive_history):
    """Save the current archive history to a log file."""
    try:
        with open(ARCHIVE_HISTORY_FILE, "w") as file:
            for path, checksum in archive_history.items():
                file.write(f"{path};{checksum}\n")
    except Exception as e:
        logging.error(f"Error saving archive history: {e}")

def should_process_archive(file_path, archive_history):
    """
    Check if an archive file should be processed.
    Compares its current checksum with the stored one.
    """
    current_checksum = calculate_checksum(file_path)
    if current_checksum is None:
        return False  # Skip processing if checksum calculation fails

    previous_checksum = archive_history.get(file_path)
    if current_checksum != previous_checksum:
        logging.info(f"Archive {file_path} has changed (checksum mismatch).")
        archive_history[file_path] = current_checksum  # Update history
        return True
    else:
        logging.info(f"Archive {file_path} has not changed.")
        return False

def query_virustotal(hash_value):
    """Query the VirusTotal API for a given hash and extract relevant fields."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY, "accept": "application/json"}

    try:
        response = requests.get(url, headers=headers)
        logging.debug(f"VirusTotal request URL: {url}")
        logging.debug(f"VirusTotal response status: {response.status_code}")
        logging.debug(f"VirusTotal response body: {response.text}")

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            yara_results = data.get("crowdsourced_yara_results", [])
            rule_names = [result.get("rule_name", "Unknown") for result in yara_results]
            return {
                "found": True,
                "magic": data.get("magic", "Unknown"),
                "creation_date": datetime.utcfromtimestamp(data.get("creation_date", 0)).strftime("%Y-%m-%d %H:%M:%S")
                if data.get("creation_date") else "Unknown",
                "meaningful_name": data.get("meaningful_name", "Unknown"),
                "common_name": data.get("popular_threat_name", "Unknown"),
                "last_analysis_stats": data.get("last_analysis_stats", {}),
                "rule_names": ", ".join(rule_names) if rule_names else "No YARA rules matched",
            }
        elif response.status_code == 404:
            logging.info(f"Hash {hash_value} not found on VirusTotal.")
            return {"found": False}
        else:
            logging.error(f"VirusTotal API error. HTTP Status Code: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Error querying VirusTotal for hash {hash_value}: {e}")
        return None

def save_processed_hash(hash_value, folder_path, file_size, vt_data):
    """Save processed hash information to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rule_names = vt_data.get("rule_names", "No YARA rules matched") if vt_data.get("found") else "Not found"
    common_name = vt_data.get("common_name", "Unknown") if vt_data.get("found") else "Not found"
    magic = vt_data.get("magic", "Unknown") if vt_data.get("found") else "Not found"
    creation_date = vt_data.get("creation_date", "Unknown") if vt_data.get("found") else "Not found"
    meaningful_name = vt_data.get("meaningful_name", "Unknown") if vt_data.get("found") else "Not found"
    stats = vt_data.get("last_analysis_stats", {}) if vt_data.get("found") else {}
    analysis_stats = f"Malicious: {stats.get('malicious', 0)}, Undetected: {stats.get('undetected', 0)}, Suspicious: {stats.get('suspicious', 0)}" if vt_data.get("found") else "Not found"

    log_entry = f"{timestamp};{hash_value};{folder_path};{file_size};{rule_names};{common_name};{magic};{creation_date};{meaningful_name};{analysis_stats}\n"

    with open(PROCESSED_HASHES_FILE, "a") as f:
        f.write(log_entry)

def extract_and_process_archive(file_path, new_hashes, processed_hashes):
    """Extract and process files from an archive."""
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            tar.extractall(path=SCAN_DIR)
            for member in tar.getmembers():
                if member.isfile():
                    extracted_file_path = os.path.join(SCAN_DIR, member.name)
                    logging.debug(f"Processing extracted file: {extracted_file_path}")
                    hash_value = os.path.basename(extracted_file_path)
                    if len(hash_value) == 32 and all(c in "0123456789abcdef" for c in hash_value):
                        process_file(hash_value, extracted_file_path, os.path.dirname(extracted_file_path), new_hashes, processed_hashes)
    except Exception as e:
        logging.error(f"Error extracting archive {file_path}: {e}")

def process_file(hash_value, file_path, folder_path, new_hashes, processed_hashes):
    """Process a single file hash."""
    if hash_value in processed_hashes:
        logging.info(f"Hash {hash_value} already processed. Skipping.")
        return

    logging.debug(f"Processing hash: {hash_value}, Full path: {file_path}")
    file_size = os.path.getsize(file_path)

    if ENABLE_CHECK:
        vt_data = query_virustotal(hash_value)
        if vt_data and vt_data["found"]:
            save_processed_hash(hash_value, folder_path, format_file_size(file_size), vt_data)
        elif vt_data and not vt_data["found"]:
            save_processed_hash(hash_value, folder_path, format_file_size(file_size), vt_data)
            save_new_hash(hash_value, folder_path, format_file_size(file_size))
            new_hashes.append(hash_value)
        else:
            logging.error(f"Error processing hash {hash_value}. Could not retrieve data from VirusTotal.")
    else:
        logging.info(f"Skipped VirusTotal check for hash: {hash_value}")

def save_new_hash(hash_value, folder_path, file_size):
    """Save new hash to new_hashes.log for notification."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp};{hash_value};{folder_path};{file_size};Not found\n"

    with open(NEW_HASHES_FILE, "a") as f:
        f.write(entry)
    return entry  # Return the entry for notifications

def process_files():
    """Process all files and specific archives in the directory."""
    new_hashes = []
    processed_hashes = load_processed_hashes()
    archive_history = load_archive_history()

    for root, _, files in os.walk(SCAN_DIR):
        if os.path.abspath(root) in EXCLUDE_DIRS:
            logging.info(f"Skipping excluded directory: {root}")
            continue

        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name in ["downloads.tgz", "binaries.tgz"]:  # Restrict to specific archives
                if should_process_archive(file_path, archive_history):
                    extract_and_process_archive(file_path, new_hashes, processed_hashes)
            elif len(file_name) == 32 and all(c in "0123456789abcdef" for c in file_name):
                process_file(file_name, file_path, root, new_hashes, processed_hashes)

    save_archive_history(archive_history)

    if new_hashes:
        send_telegram_notification(new_hashes)

if __name__ == "__main__":
    process_files()
