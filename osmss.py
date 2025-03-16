import requests
import csv
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import time
import hashlib
import threading
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
import mmap

MALSHARE_API_KEY = "YOUR_API_KEY_HERE"
SIGNATURE_SOURCES = [
    ("AbuseCh", "https://bazaar.abuse.ch/export/csv/full/", "csv", 1),
    ("Malshare", f"https://malshare.com/api.php?api_key={MALSHARE_API_KEY}&action=getlist", "txt", None),
    ("OpenMalware", "https://raw.githubusercontent.com/absolomb/malware-hashes/master/hashes.txt", "txt", None)
]
CACHE_DURATION = 86400
DOWNLOAD_TIMEOUT = 30

def download_source(source_name, url, dest_file, force_download=False):
    if os.path.exists(dest_file) and not force_download:
        file_age = time.time() - os.path.getmtime(dest_file)
        if file_age < CACHE_DURATION:
            print(f"[{source_name}] Using cached file: {dest_file}")
            return
    try:
        print(f"[{source_name}] Downloading from {url} ...")
        response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0
        with open(dest_file, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    print(f"[{source_name}] Download progress: {downloaded_size / total_size * 100:.2f}%")
    except Exception as e:
        print(f"[{source_name}] Failed to download data: {e}")
        raise

def load_signatures_from_file(source_name, file_path, file_type, hash_col_index):
    signatures = set()
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            if file_type.lower() == "csv":
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) > hash_col_index:
                        sig = row[hash_col_index].strip().lower()
                        if sig:
                            signatures.add(sig)
            elif file_type.lower() == "txt":
                for line in f:
                    sig = line.strip().lower()
                    if sig:
                        signatures.add(sig)
            else:
                print(f"[{source_name}] Unknown file type: {file_type}")
    except Exception as e:
        print(f"[{source_name}] Error parsing file {file_path}: {e}")
    print(f"[{source_name}] Loaded {len(signatures)} signatures.")
    return signatures

def load_all_signatures(force_download=False):
    combined_signatures = set()
    for source_name, url, file_type, hash_col_index in SIGNATURE_SOURCES:
        local_file = f"{source_name.lower()}_signatures.csv" if file_type.lower() == "csv" else f"{source_name.lower()}_signatures.txt"
        try:
            download_source(source_name, url, local_file, force_download=force_download)
            source_sigs = load_signatures_from_file(source_name, local_file, file_type, hash_col_index)
            combined_signatures.update(source_sigs)
        except Exception as e:
            print(f"Error processing {source_name}: {e}")
    print(f"Total combined signatures: {len(combined_signatures)}")
    return combined_signatures

def compute_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            try:
                file_size = os.path.getsize(file_path)
                if file_size > 0:
                    with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                        sha256_hash.update(mm)
                else:
                    sha256_hash.update(b"")
            except Exception:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Cannot read file {file_path}: {e}")
        return None

def check_file_for_signatures(file_path, signatures, ui_queue, log_queue):
    file_hash = compute_hash(file_path)
    if file_hash:
        log_queue.put(f"Scanned {file_path} (hash: {file_hash[:8]}...)")
        if file_hash.lower() in signatures:
            ui_queue.put((file_path, "matched"))
            log_queue.put(f"Malware detected: {file_path}")
            return file_path
    ui_queue.put((file_path, "scanned"))
    return None

def scan_files(file_paths, signatures, ui_queue, log_queue, stop_event):
    matched_files = []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = {}
        for file_path in file_paths:
            if stop_event.is_set():
                break
            future = executor.submit(check_file_for_signatures, file_path, signatures, ui_queue, log_queue)
            futures[future] = file_path
        for future in futures:
            if stop_event.is_set():
                break
            try:
                result = future.result()
                if result:
                    matched_files.append(result)
            except Exception as e:
                log_queue.put(f"Error scanning {futures[future]}: {e}")
    return matched_files

class OSMSS:
    def __init__(self, master):
        self.master = master
        master.title("OSMSS v1.0.8")
        master.geometry("1000x700")
        master.configure(bg="#000000")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TProgressbar", troughcolor="#000000", background="#00ff00", thickness=20)
        self.top_frame = tk.Frame(master, bg="#000000")
        self.top_frame.pack(fill=tk.X, padx=10, pady=10)
        logo_text = "OSMSS"
        self.logo_label = tk.Label(self.top_frame, text=logo_text,
                                   font=("Consolas", 28, "bold"),
                                   bg="#000000", fg="#00ff00")
        self.logo_label.pack()
        self.control_frame = tk.Frame(master, bg="#000000")
        self.control_frame.pack(fill=tk.X, padx=10, pady=10)
        self.select_dir_button = tk.Button(self.control_frame, text="Select Directory",
                                           command=self.select_directory,
                                           font=("Consolas", 12), bg="#000000", fg="#00ff00",
                                           activebackground="#000000", activeforeground="#00ff00", bd=0)
        self.select_dir_button.pack(side=tk.LEFT, padx=5)
        self.start_scan_button = tk.Button(self.control_frame, text="Start Scan",
                                           command=self.start_scan,
                                           font=("Consolas", 12), bg="#000000", fg="#00ff00",
                                           activebackground="#000000", activeforeground="#00ff00", bd=0, state=tk.DISABLED)
        self.start_scan_button.pack(side=tk.LEFT, padx=5)
        self.stop_scan_button = tk.Button(self.control_frame, text="Stop Scan",
                                          command=self.stop_scan,
                                          font=("Consolas", 12), bg="#000000", fg="#00ff00",
                                          activebackground="#000000", activeforeground="#00ff00", bd=0, state=tk.DISABLED)
        self.stop_scan_button.pack(side=tk.LEFT, padx=5)
        self.export_button = tk.Button(self.control_frame, text="Export CSV",
                                       command=self.export_results,
                                       font=("Consolas", 12), bg="#000000", fg="#00ff00",
                                       activebackground="#000000", activeforeground="#00ff00", bd=0, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=5)
        self.progress_frame = tk.Frame(master, bg="#000000")
        self.progress_frame.pack(fill=tk.X, padx=10, pady=5)
        self.progress_bar = ttk.Progressbar(self.progress_frame, length=800, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, padx=5, pady=5)
        self.percentage_label = tk.Label(self.progress_frame, text="0%",
                                         font=("Consolas", 12),
                                         bg="#000000", fg="#00ff00")
        self.percentage_label.pack(side=tk.LEFT, padx=5)
        self.status_frame = tk.Frame(master, bg="#000000")
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)
        self.status_label = tk.Label(self.status_frame, text="Status: Waiting to start scan",
                                     font=("Consolas", 12),
                                     bg="#000000", fg="#00ff00")
        self.status_label.pack(side=tk.LEFT)
        self.log_frame = tk.Frame(master, bg="#000000")
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.log_text = tk.Text(self.log_frame, bg="#000000", fg="#00ff00", wrap=tk.WORD,
                                font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)
        self.file_paths = []
        self.ui_queue = Queue()
        self.log_queue = Queue()
        self.stop_event = threading.Event()
        self.matched_files = []
        self.total_files = 0
        self.processed_count = 0
        self.start_time = None

    def select_directory(self):
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            self.status_label.config(text=f"Collecting files in: {selected_dir}...")
            threading.Thread(target=self.collect_files, args=(selected_dir,), daemon=True).start()

    def collect_files(self, selected_dir):
        file_paths = []
        for foldername, _, filenames in os.walk(selected_dir):
            for filename in filenames:
                full_path = os.path.join(foldername, filename)
                file_paths.append(full_path)
        self.master.after(0, lambda: self.on_files_collected(file_paths, selected_dir))

    def on_files_collected(self, file_paths, selected_dir):
        self.file_paths = file_paths
        self.total_files = len(self.file_paths)
        self.progress_bar['maximum'] = self.total_files
        self.status_label.config(text=f"Directory selected: {selected_dir}. Total files: {self.total_files}")
        self.start_scan_button.config(state=tk.NORMAL)

    def start_scan(self):
        if not self.file_paths:
            messagebox.showwarning("No directory selected", "Please select a directory to scan.")
            return
        self.stop_event.clear()
        self.start_scan_button.config(state=tk.DISABLED)
        self.stop_scan_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.DISABLED)
        self.processed_count = 0
        self.start_time = time.time()
        threading.Thread(target=self.prepare_and_scan, daemon=True).start()
        self.master.after(100, self.update_ui)

    def prepare_and_scan(self):
        try:
            signatures = load_all_signatures()
        except Exception as e:
            self.log(f"Error preparing malware data: {e}")
            return
        self.log("Starting scan...")
        matched = scan_files(self.file_paths, signatures, self.ui_queue, self.log_queue, self.stop_event)
        self.matched_files = matched
        self.log("Scan complete.")
        self.master.after(0, lambda: self.export_button.config(state=tk.NORMAL))
        try:
            with open("matched_files.txt", "w") as f:
                for file in self.matched_files:
                    f.write(file + "\n")
            self.log("Matched files saved to matched_files.txt")
        except Exception as e:
            self.log(f"Error saving matched files: {e}")

    def update_ui(self):
        while not self.ui_queue.empty():
            try:
                file_path, status = self.ui_queue.get_nowait()
                self.processed_count += 1
                self.progress_bar['value'] = self.processed_count
                progress_percentage = (self.processed_count / self.total_files) * 100
                self.percentage_label.config(text=f"{progress_percentage:.2f}%")
                self.status_label.config(text=f"{status.capitalize()}: {file_path}")
                self.ui_queue.task_done()
            except Empty:
                break
        while not self.log_queue.empty():
            try:
                log_message = self.log_queue.get_nowait()
                self.append_log(log_message)
                self.log_queue.task_done()
            except Empty:
                break

        if self.start_time and self.processed_count < self.total_files:
            elapsed_time = time.time() - self.start_time
            files_per_second = self.processed_count / elapsed_time if elapsed_time > 0 else 0
            remaining_files = self.total_files - self.processed_count
            remaining_time = remaining_files / files_per_second if files_per_second > 0 else 0
            minutes, seconds = divmod(int(remaining_time), 60)
            self.status_label.config(text=f"Scanning... Estimated time left: {minutes}m {seconds}s")
            self.master.after(100, self.update_ui)
        else:
            self.stop_scan_button.config(state=tk.DISABLED)
            self.start_scan_button.config(state=tk.NORMAL)

    def stop_scan(self):
        self.stop_event.set()
        self.log("Scan stopped by user.")
        self.stop_scan_button.config(state=tk.DISABLED)
        self.start_scan_button.config(state=tk.NORMAL)

    def export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title="Save scan results"
        )
        if not file_path:
            return
        try:
            with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["File Path"])
                for matched_file in self.matched_files:
                    writer.writerow([matched_file])
            messagebox.showinfo("Export Complete", f"Results exported successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results: {e}")

    def append_log(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def log(self, message):
        self.log_queue.put(message)

if __name__ == "__main__":
    root = tk.Tk()
    app = OSMSS(root)
    root.mainloop()
