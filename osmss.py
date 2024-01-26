import requests
import csv
import os
import tkinter as tk
from tkinter import ttk
import time
import hashlib

def download_malware_data(url):
    try:
        with requests.get(url) as response:
            response.raise_for_status()
            with open("full.csv", "wb") as f:
                f.write(response.content)
    except Exception as e:
        print(f"Failed to download malware data: {e}")
        exit()

def load_malicious_signatures(csv_file):
    malicious_signatures = set()
    try:
        with open(csv_file, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) > 1:
                    malicious_signatures.add(row[1])
    except Exception as e:
        print(f"Error loading malicious signatures: {e}")
    return malicious_signatures

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Cannot read file {file_path} due to {e}")
        return None

def check_file_for_signatures(file_path, malicious_signatures):
    file_hash = compute_hash(file_path)
    if file_hash and file_hash in malicious_signatures:
        return file_path
    return None

def scan_files(malicious_signatures, all_files, update_ui_callback):
    matched_files = []
    start_time = time.time()
    for i, file_path in enumerate(all_files):
        matched_file = check_file_for_signatures(file_path, malicious_signatures)
        if matched_file:
            matched_files.append(matched_file)
        update_ui_callback(i, file_path, len(all_files), start_time)
    return matched_files

def main():
    malware_data_url = "https://bazaar.abuse.ch/export/csv/full/"
    download_malware_data(malware_data_url)
    malicious_signatures = load_malicious_signatures("full.csv")
    all_files = [os.path.join(foldername, filename) 
                 for foldername, _, filenames in os.walk("C:\") 
                 for filename in filenames]

    def update_ui(i, file_path, total_files, start_time):
        progress_bar['value'] = i
        percentage = (i / total_files) * 100
        percentage_label['text'] = f"{percentage:.2f}%"
        file_label['text'] = f"Scanning: {file_path}"
        elapsed_time = time.time() - start_time
        files_per_second = i / elapsed_time if elapsed_time > 0 else 0
        remaining_files = total_files - i
        remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
        minutes, seconds = divmod(int(remaining_time), 60)
        time_label['text'] = f"Estimated time left: {minutes}m {seconds}s"
        window.update_idletasks()
    window = tk.Tk()
    window.title("OSMSS")
    window.geometry("800x400")
    window.configure(bg='black')
    ascii_logo = """
 
 $$$$$$\   $$$$$$\  $$\      $$\  $$$$$$\   $$$$$$\  
$$  __$$\ $$  __$$\ $$$\    $$$ |$$  __$$\ $$  __$$\ 
$$ /  $$ |$$ /  \__|$$$$\  $$$$ |$$ /  \__|$$ /  \__|
$$ |  $$ |\$$$$$$\  $$\$$\$$ $$ |\$$$$$$\  \$$$$$$\  
$$ |  $$ | \____$$\ $$ \$$$  $$ | \____$$\  \____$$\ 
$$ |  $$ |$$\   $$ |$$ |\$  /$$ |$$\   $$ |$$\   $$ |
 $$$$$$  |\$$$$$$  |$$ | \_/ $$ |\$$$$$$  |\$$$$$$  |
 \______/  \______/ \__|     \__| \______/  \______/  
      
"""
    logo_label = tk.Label(window, text=ascii_logo, bg='black', fg='green', font=("Courier", 12))
    logo_label.pack()
    progress_bar = ttk.Progressbar(window, length=500, mode='determinate', maximum=len(all_files))
    progress_bar.pack()
    percentage_label = tk.Label(window, text="0%", bg='black', fg='green', font=("Helvetica", 16))
    percentage_label.pack()
    file_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12))
    file_label.pack()
    time_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12))
    time_label.pack()

    matched_files = scan_files(malicious_signatures, all_files, update_ui)
    with open("matched_files.txt", "w") as f:
        for matched_file in matched_files:
            f.write(matched_file + "\n")
    window.mainloop()
if __name__ == "__main__":
    main()
