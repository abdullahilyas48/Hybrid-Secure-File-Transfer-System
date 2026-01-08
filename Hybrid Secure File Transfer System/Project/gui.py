# gui.py - Optional simple Tkinter GUI for selecting a file and sending locally via socket_sender.py
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

def browse_file(entry):
    path = filedialog.askopenfilename(initialdir=str(PROJECT_ROOT / 'tests' / 'samples'))
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)

def send_file(file_path, ip, port, pubkey):
    # This GUI assumes socket_sender.py is available and executable
    cmd = [sys.executable, str(PROJECT_ROOT / 'socket_sender.py'),
           '--file', file_path, '--ip', ip, '--port', str(port), '--pubkey', pubkey]
    try:
        subprocess.check_call(cmd)
        messagebox.showinfo('Success', 'File sent successfully.')
    except subprocess.CalledProcessError as e:
        messagebox.showerror('Error', f'Sending failed: {e}')

def on_send(file_entry, ip_entry, port_entry, pubkey_entry):
    file_path = file_entry.get().strip()
    ip = ip_entry.get().strip() or '127.0.0.1'
    port = int(port_entry.get().strip() or 5001)
    pubkey = pubkey_entry.get().strip() or str(PROJECT_ROOT / 'receiver_public.pem')
    if not file_path:
        messagebox.showwarning('Missing', 'Please select a file.')
        return
    send_file(file_path, ip, port, pubkey)

def build_gui():
    root = tk.Tk()
    root.title('Hybrid Secure File Sender')

    tk.Label(root, text='File:').grid(row=0, column=0, sticky='e')
    file_entry = tk.Entry(root, width=50)
    file_entry.grid(row=0, column=1, padx=4, pady=4)
    tk.Button(root, text='Browse', command=lambda: browse_file(file_entry)).grid(row=0, column=2, padx=4)

    tk.Label(root, text='Receiver IP:').grid(row=1, column=0, sticky='e')
    ip_entry = tk.Entry(root, width=20)
    ip_entry.grid(row=1, column=1, sticky='w', padx=4, pady=4)
    ip_entry.insert(0, '127.0.0.1')

    tk.Label(root, text='Port:').grid(row=2, column=0, sticky='e')
    port_entry = tk.Entry(root, width=10)
    port_entry.grid(row=2, column=1, sticky='w', padx=4, pady=4)
    port_entry.insert(0, '5001')

    tk.Label(root, text='Receiver Public Key:').grid(row=3, column=0, sticky='e')
    pubkey_entry = tk.Entry(root, width=50)
    pubkey_entry.grid(row=3, column=1, padx=4, pady=4)
    pubkey_entry.insert(0, str(PROJECT_ROOT / 'receiver_public.pem'))

    tk.Button(root, text='Send Securely', command=lambda: on_send(file_entry, ip_entry, port_entry, pubkey_entry)).grid(row=4, column=1, pady=10)

    root.mainloop()

if __name__ == '__main__':
    build_gui()
