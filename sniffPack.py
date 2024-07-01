import tkinter as tk
from tkinter import ttk
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import threading
import os
import warnings

# Suppress specific warnings
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*cannot read manuf.*")

# Set SCAPY_MANUF_PATH if needed
os.environ['SCAPY_MANUF_PATH'] = 'path_to_manuf_file'  # Replace with the actual path

# Define colors
COLOR_BG = "#e0fbfc"
COLOR_BTN = "#3d5a80"
COLOR_BTN_TEXT = "#e0fbfc"
COLOR_BTN_DISABLED = "#98c1d9"
COLOR_EXIT_BTN = "#ee6c4d"
COLOR_HEADER = "#293241"
COLOR_HEADER_TEXT = "#000000"  # Black color for header text
COLOR_TEXT = "#293241"

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer Tool")
        self.root.configure(bg=COLOR_BG)

        # Create UI elements
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing, 
                                      bg=COLOR_BTN, fg=COLOR_BTN_TEXT, activebackground=COLOR_BTN_DISABLED)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, 
                                     bg=COLOR_BTN_DISABLED, fg=COLOR_BTN_TEXT, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.exit_button = tk.Button(root, text="Exit", command=root.quit, bg=COLOR_EXIT_BTN, fg=COLOR_BTN_TEXT)
        self.exit_button.pack(pady=5)

        style = ttk.Style()
        style.configure("Treeview.Heading", background=COLOR_HEADER, foreground=COLOR_HEADER_TEXT, font=("Helvetica", 10, "bold"))
        style.configure("Treeview", background=COLOR_BG, fieldbackground=COLOR_BG, foreground=COLOR_TEXT)
        
        self.tree = ttk.Treeview(root, columns=("src_ip", "dst_ip", "protocol", "payload"), show="headings")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("payload", text="Payload")
        self.tree.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)

        self.sniffing = False
        self.sniff_thread = None

    def analyze_packet(self, packet):
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto

            protocol_name = "Unknown"
            payload = ""

            if protocol == 6:  # TCP
                protocol_name = "TCP"
                if TCP in packet:
                    payload = packet[TCP].payload
            elif protocol == 17:  # UDP
                protocol_name = "UDP"
                if UDP in packet:
                    payload = packet[UDP].payload

            self.tree.insert("", tk.END, values=(src_ip, dst_ip, protocol_name, payload))

    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.start_button.config(state=tk.DISABLED, bg=COLOR_BTN_DISABLED)
            self.stop_button.config(state=tk.NORMAL, bg=COLOR_BTN)
            self.sniff_thread = threading.Thread(target=self.sniff_packets)
            self.sniff_thread.start()

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button.config(state=tk.NORMAL, bg=COLOR_BTN)
            self.stop_button.config(state=tk.DISABLED, bg=COLOR_BTN_DISABLED)
            if self.sniff_thread:
                self.sniff_thread.join()

    def sniff_packets(self):
        sniff(prn=self.analyze_packet, store=0, stop_filter=lambda p: not self.sniffing)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
