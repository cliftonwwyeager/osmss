import requests
import csv
import os
import tkinter as tk
from tkinter import ttk
import time
import hashlib

# URL to MalwareBazaar or your chosen source of malware data
malware_data_url = "https://bazaar.abuse.ch/export/csv/full/"

# Download malware data and save it as a CSV file
response = requests.get(malware_data_url)

if response.status_code == 200:
    with open("full.csv", "wb") as f:
        f.write(response.content)
else:
    print("Failed to download malware data")
    exit()

# Load malicious signatures from the CSV file
malicious_signatures = set()
with open("full.csv", "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    next(reader)  # Skip the header row
    for row in reader:
        if len(row) > 1:  # Ensure the row has enough data
            malicious_signatures.add(row[1])  # Assuming signature is in the 2nd column

# Function to compute the SHA-256 hash of a file
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

# Function to check if file hash matches any malicious signature
def check_file_for_signatures(file_path):
    file_hash = compute_hash(file_path)
    if file_hash and file_hash in malicious_signatures:
        return file_path
    return None

# Get list of all files in C drive
all_files = [os.path.join(foldername, filename) 
             for foldername, _, filenames in os.walk("C:\\") 
             for filename in filenames]

# Create and configure the main window
window = tk.Tk()
window.title("OSMSS")
window.geometry("800x400")
window.configure(bg='black')

# ASCII Logo
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

# Add a progress bar to display the scan progress
progress_bar = ttk.Progressbar(window, length=500, mode='determinate', maximum=len(all_files))
progress_bar.grid(column=0, row=0, pady=20, padx=20, columnspan=2)

# Label to show percentage
percentage_label = tk.Label(window, text="0%", bg='black', fg='green', font=("Helvetica", 16))
percentage_label.grid(column=2, row=0, pady=20, padx=20)

# Label to show the file being scanned
file_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
file_label.grid(column=0, row=1, pady=10, padx=20, columnspan=3)

# Label to show estimated time left
time_label = tk.Label(window, text="", bg='black', fg='green', font=("Helvetica", 12), wraplength=550)
time_label.grid(column=0, row=2, pady=10, padx=20, columnspan=3)

# Check files in C drive against malicious signatures and update the UI
matched_files = []
start_time = time.time()
for i, file_path in enumerate(all_files):
    window.update()  # Update the UI
    matched_file = check_file_for_signatures(file_path)
    if matched_file:
        matched_files.append(matched_file)
    
    # Update progress bar, percentage label, and file label
    progress_bar['value'] = i
    percentage_label['text'] = f"{(i/len(all_files))*100:.2f}%"
    file_label['text'] = f"Scanning: {file_path}"
    
    # Calculate and update estimated time left
    elapsed_time = time.time() - start_time
    files_per_second = i / elapsed_time if elapsed_time > 0 else 0
    remaining_files = len(all_files) - i
    remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
    minutes, seconds = divmod(int(remaining_time), 60)
    time_label['text'] = f"Estimated time left: {minutes}m {seconds}s"
    
    window.update_idletasks()

# Write matched file names to a .txt file
with open("matched_files.txt", "w") as f:
    for matched_file in matched_files:
        f.write(matched_file + "\n")

# Start the Tkinter event loop
window.mainloop()
