import requests
import csv
import os
import tkinter as tk
from tkinter import ttk
import time
import hashlib
import threading
from queue import Queue

MALWARE_DATA_URL = "https://bazaar.abuse.ch/export/csv/full/"
CSV_FILE = "full.csv"
MALWARE_HASH_COL_INDEX = 1

def download_malware_data():
    response = requests.get(MALWARE_DATA_URL, stream=True)
    if response.status_code == 200:
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        with open(CSV_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    print(f"Downloading: {downloaded_size / total_size * 100:.2f}%")
    else:
        print("Failed to download malware data")
        exit()

def load_malicious_signatures():
    signatures = set()
    try:
        with open(CSV_FILE, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) > MALWARE_HASH_COL_INDEX:
                    signatures.add(row[MALWARE_HASH_COL_INDEX])
    except FileNotFoundError:
        print(f"{CSV_FILE} not found. Please download the malware data.")
        exit()
    except Exception as e:
        print(f"Error loading signatures: {e}")
        exit()
    return signatures

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Cannot read file {file_path} due to {str(e)}")
        return None

def check_file_for_signatures(file_path, signatures, ui_queue):
    file_hash = compute_hash(file_path)
    if file_hash and file_hash in signatures:
        ui_queue.put((file_path, "matched"))
    ui_queue.put((file_path, "scanned"))
    return file_path if file_hash and file_hash in signatures else None

def scan_files(queue, signatures, matched_files, ui_queue):
    while not queue.empty():
        file_path = queue.get()
        matched_file = check_file_for_signatures(file_path, signatures, ui_queue)
        if matched_file:
            matched_files.append(matched_file)
        queue.task_done()

def update_ui(ui_queue, start_time, progress_bar, percentage_label, file_label, time_label, total_files):
    while True:
        try:
            file_path, status = ui_queue.get_nowait()
        except Queue.Empty:
            break
        
        progress = total_files - file_queue.qsize()
        progress_percentage = (progress / total_files) * 100
        elapsed_time = time.time() - start_time
        files_per_second = progress / elapsed_time if elapsed_time > 0 else 0
        remaining_files = file_queue.qsize()
        remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
        minutes, seconds = divmod(int(remaining_time), 60)
        
        progress_bar['value'] = progress
        percentage_label.config(text=f"{progress_percentage:.2f}%")
        file_label.config(text=f"Scanning: {file_path}" if status == "scanned" else "Scanning completed")
        time_label.config(text=f"Estimated time left: {minutes}m {seconds}s")

        ui_queue.task_done()

    root.after(1000, update_ui, ui_queue, start_time, progress_bar, percentage_label, file_label, time_label, total_files)

if __name__ == "__main__":
    download_malware_data()
    malicious_signatures = load_malicious_signatures()

    all_files = [os.path.join(foldername, filename) 
                for foldername, _, filenames in os.walk("C:\\") 
                for filename in filenames]

    root = tk.Tk()
    root.title("OSMSS v1.0.5")
    root.geometry("800x400")
    root.configure(bg='black')

    ascii_logo = """
     $$$$$$\\   $$$$$$\\  $$\\      $$\\  $$$$$$\\   $$$$$$\\  
    $$  __$$\\ $$  __$$\\ $$$\\    $$$ |$$  __$$\\ $$  __$$\\ 
    $$ /  $$ |$$ /  \\__|$$$$\\  $$$$ |$$ /  \\__|$$ /  \\__|
    $$ |  $$ |\\$$$$$$\\  $$\\$$\\$$ $$ |\\$$$$$$\\  \\$$$$$$\\  
    $$ |  $$ | \\____$$\\ $$ \\$$$  $$ | \\____$$\\  \\____$$\\ 
    $$ |  $$ |$$\\   $$ |$$ |\\$  /$$ |$$\\   $$ |$$\\   $$ |
     $$$$$$  |\\$$$$$$  |$$ | \\_/ $$ |\\$$$$$$  |\\$$$$$$  |
     \\______/  \\______/ \\__|     \\__| \\______/  \\______/  
    """
    logo_label = tk.Label(root, text=ascii_logo, bg='black', fg='green', font=("Courier", 12))
    logo_label.grid(column=0, row=0, pady=10, padx=20, columnspan=3)

    progress_bar = ttk.Progressbar(root, length=500, mode='determinate', maximum=len(all_files))
    progress_bar.grid(column=0, row=1, pady=20, padx=20, columnspan=2)

    percentage_label = tk.Label(root, text="0%", bg='black', fg='green', font=("Helvetica", 16))
    percentage_label.grid(column=2, row=1, pady=20, padx=20)

    file_label = tk.Label(root, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
    file_label.grid(column=0, row=2, pady=10, padx=20, columnspan=3)

    time_label = tk.Label(root, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
    time_label.grid(column=0, row=3, pady=10, padx=20, columnspan=3)

    matched_files = []
    file_queue = Queue()
    ui_queue = Queue()

    for file_path in all_files:
        file_queue.put(file_path)

    start_time = time.time()

    for _ in range(os.cpu_count()):
        worker = threading.Thread(target=scan_files, args=(file_queue, malicious_signatures, matched_files, ui_queue))
        worker.daemon = True
        worker.start()

    root.after(1000, update_ui, ui_queue, start_time, progress_bar, percentage_label, file_label, time_label, len(all_files))
    
    root.mainloop()

    file_queue.join()
    ui_queue.join()

    with open("matched_files.txt", "w") as f:
        for matched_file in matched_files:
            f.write(matched_file + "\n")
