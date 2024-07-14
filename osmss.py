import requests
import csv
import os
import tkinter as tk
from tkinter import ttk
import time
import hashlib
import threading
from queue import Queue

malware_data_url = "https://bazaar.abuse.ch/export/csv/full/"

def download_malware_data():
    response = requests.get(malware_data_url, stream=True)
    if response.status_code == 200:
        with open("full.csv", "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    else:
        print("Failed to download malware data")
        exit()

def load_malicious_signatures():
    signatures = set()
    with open("full.csv", "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if len(row) > 1:
                signatures.add(row[1])
    return signatures

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Cannot read file {file_path} due to {str(e)}")
        return None

def check_file_for_signatures(file_path, signatures):
    file_hash = compute_hash(file_path)
    if file_hash and file_hash in signatures:
        return file_path
    return None

def scan_files(queue, signatures, matched_files):
    while not queue.empty():
        file_path = queue.get()
        matched_file = check_file_for_signatures(file_path, signatures)
        if matched_file:
            matched_files.append(matched_file)
        queue.task_done()

def update_ui(queue, matched_files, start_time, progress_bar, percentage_label, file_label, time_label, total_files):
    while not queue.empty():
        progress = total_files - queue.qsize()
        progress_bar['value'] = progress
        percentage_label['text'] = f"{(progress/total_files)*100:.2f}%"
        file_label['text'] = f"Scanning: {queue.queue[0]}" if not queue.empty() else "Scanning completed"
        elapsed_time = time.time() - start_time
        files_per_second = progress / elapsed_time if elapsed_time > 0 else 0
        remaining_files = queue.qsize()
        remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
        minutes, seconds = divmod(int(remaining_time), 60)
        time_label['text'] = f"Estimated time left: {minutes}m {seconds}s"
        window.update_idletasks()
        time.sleep(1)

if __name__ == "__main__":
    download_malware_data()
    malicious_signatures = load_malicious_signatures()

    all_files = [os.path.join(foldername, filename) 
                for foldername, _, filenames in os.walk("C:\\") 
                for filename in filenames]

    window = tk.Tk()
    window.title("OSMSS v1.0.3")
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
    logo_label.grid(column=0, row=0, pady=10, padx=20, columnspan=3)

    progress_bar = ttk.Progressbar(window, length=500, mode='determinate', maximum=len(all_files))
    progress_bar.grid(column=0, row=1, pady=20, padx=20, columnspan=2)

    percentage_label = tk.Label(window, text="0%", bg='black', fg='green', font=("Helvetica", 16))
    percentage_label.grid(column=2, row=1, pady=20, padx=20)

    file_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
    file_label.grid(column=0, row=2, pady=10, padx=20, columnspan=3)

    time_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
    time_label.grid(column=0, row=3, pady=10, padx=20, columnspan=3)

    matched_files = []
    file_queue = Queue()

    for file_path in all_files:
        file_queue.put(file_path)

    start_time = time.time()

    for _ in range(os.cpu_count()):
        worker = threading.Thread(target=scan_files, args=(file_queue, malicious_signatures, matched_files))
        worker.daemon = True
        worker.start()

    ui_thread = threading.Thread(target=update_ui, args=(file_queue, matched_files, start_time, progress_bar, percentage_label, file_label, time_label, len(all_files)))
    ui_thread.daemon = True
    ui_thread.start()

    file_queue.join()
    ui_thread.join()

    with open("matched_files.txt", "w") as f:
        for matched_file in matched_files:
            f.write(matched_file + "\n")

    window.mainloop()
