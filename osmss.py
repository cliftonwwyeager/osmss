import requests
import csv
import os
import tkinter as tk
from tkinter import ttk
import time
import hashlib

malware_data_url = "https://bazaar.abuse.ch/export/csv/full/"

response = requests.get(malware_data_url, stream=True)
if response.status_code == 200:
    with open("full.csv", "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
else:
    print("Failed to download malware data")
    exit()

malicious_signatures = set()
with open("full.csv", "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        if len(row) > 1:
            malicious_signatures.add(row[1])

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path,"rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Cannot read file {file_path} due to {str(e)}")
        return None

def check_file_for_signatures(file_path):
    file_hash = compute_hash(file_path)
    if file_hash and file_hash in malicious_signatures:
        return file_path
    return None

all_files = set(os.path.join(foldername, filename) 
               for foldername, _, filenames in os.walk("C:\\") 
               for filename in filenames)

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
progress_bar.grid(column=0, row=0, pady=20, padx=20, columnspan=2)
percentage_label = tk.Label(window, text="0%", bg='black', fg='green', font=("Helvetica", 16))
percentage_label.grid(column=2, row=0, pady=20, padx=20)
file_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
file_label.grid(column=0, row=1, pady=10, padx=20, columnspan=3)
time_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
time_label.grid(column=0, row=2, pady=10, padx=20, columnspan=3)
matched_files = []

start_time = time.time()
for i, file_path in enumerate(all_files):
    matched_file = check_file_for_signatures(file_path)
    if matched_file:
        matched_files.append(matched_file)
    if i % 100 == 0:
        window.update()
        progress_bar['value'] = i
        percentage_label['text'] = f"{(i/len(all_files))*100:.2f}%"
        file_label['text'] = f"Scanning: {file_path}"
        elapsed_time = time.time() - start_time
        files_per_second = i / elapsed_time if elapsed_time > 0 else 0
        remaining_files = len(all_files) - i
        remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
        minutes, seconds = divmod(int(remaining_time), 60)
        time_label['text'] = f"Estimated time left: {minutes}m {seconds}s"

with open("matched_files.txt", "w") as f:
    for matched_file in matched_files:
        f.write(matched_file + "\n")

window.mainloop()
