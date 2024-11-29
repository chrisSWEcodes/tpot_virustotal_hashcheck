import os
import json
import requests
import logging
from datetime import datetime

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

def query_virustotal(hash_value):
    """Query the VirusTotal API for a given hash and extract relevant fields."""
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY, "accept": "application/json"}

    try:
        response = requests.get(url, headers=headers)
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

def upload_file_to_virustotal(file_path):
    """Upload a file to VirusTotal."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                logging.info(f"File {file_path} uploaded to VirusTotal.")
            else:
                logging.error(f"Failed to upload file {file_path}. HTTP Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error uploading file {file_path} to VirusTotal: {e}")

def send_telegram_notification(new_hashes):
    """Send a Telegram notification with new hashes."""
    try:
        message = "The following hashes were not found on VirusTotal and were uploaded:\n\n" + "\n".join(new_hashes)
        url = f"https://api.telegram.org/bot{TELEGRAM_SETTINGS['bot_token']}/sendMessage"
        response = requests.post(url, data={"chat_id": TELEGRAM_SETTINGS["chat_id"], "text": message})
        if response.status_code == 200:
            logging.info("Telegram notification sent successfully!")
        else:
            logging.error(f"Failed to send Telegram notification. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logging.error(f"Error sending Telegram notification: {e}")

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

def save_new_hash(hash_value, folder_path, file_size):
    """Save new hash to new_hashes.log for email notification."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp};{hash_value};{folder_path};{file_size};Not found\n"

    with open(NEW_HASHES_FILE, "a") as f:
        f.write(entry)
    return entry  # Return the entry for notifications

def process_file(hash_value, file_path, folder_path, new_hashes, processed_hashes):
    """Process a single file hash."""
    if hash_value in processed_hashes:
        logging.info(f"Hash {hash_value} already processed. Skipping.")
        return

    file_size = format_file_size(os.path.getsize(file_path))

    if ENABLE_CHECK:
        vt_data = query_virustotal(hash_value)
        if vt_data and vt_data["found"]:
            save_processed_hash(hash_value, folder_path, file_size, vt_data)
        elif vt_data and not vt_data["found"]:
            save_new_hash(hash_value, folder_path, file_size)
            save_processed_hash(hash_value, folder_path, file_size, vt_data)
            new_hashes.append(f"{hash_value};{folder_path};{file_size};Not found")
            upload_file_to_virustotal(file_path)
        else:
            logging.info(f"Hash {hash_value} could not be processed.")
    else:
        logging.info(f"Skipped VirusTotal check for hash: {hash_value}")

def process_files():
    """Process all files in the directory."""
    new_hashes = []
    processed_hashes = load_processed_hashes()

    for root, _, files in os.walk(SCAN_DIR):
        if os.path.abspath(root) in EXCLUDE_DIRS:
            logging.info(f"Skipping excluded directory: {root}")
            continue

        for file_name in files:
            file_path = os.path.join(root, file_name)

            if len(file_name) == 32 and all(c in "0123456789abcdef" for c in file_name):
                logging.info(f"Processing hash: {file_name} (Path: {file_path})")
                process_file(file_name, file_path, root, new_hashes, processed_hashes)

    if new_hashes:
        send_telegram_notification(new_hashes)

if __name__ == "__main__":
    process_files()
