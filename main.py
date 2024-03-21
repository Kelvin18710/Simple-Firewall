import time
import tkinter as tk
from tkinter import messagebox
import threading
import socket
from server import run_server


class FirewallApp:
    def __init__(self, master):  # UI
        self.server_running = False
        self.server_thread = None
        self.thread_stop_event = threading.Event()
        self.master = master

        master.title("防火墙配置")

        # 添加两个按钮，用于启用和禁用黑名单和白名单
        self.enable_blacklist_button = tk.Button(master, text="启用黑名单", command=self.enable_blacklist)
        self.enable_blacklist_button.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        self.enable_whitelist_button = tk.Button(master, text="启用白名单", command=self.enable_whitelist)
        self.enable_whitelist_button.grid(row=4, column=0, padx=5, pady=5, sticky=tk.E)

        # 初始化黑名单和白名单状态
        self.blacklist_enabled = True
        self.whitelist_enabled = False
        self.enable_blacklist_button["state"] = tk.DISABLED
        self.enable_whitelist_button["state"] = tk.NORMAL
        self.enable_blacklist_button["text"] = "黑名单已启用"
        self.enable_whitelist_button["text"] = "启用白名单"

        # 黑名单部分
        self.blacklist_label = tk.Label(master, text="黑名单:")
        self.blacklist_label.grid(row=0, column=0, sticky=tk.W)

        self.blacklist_entry = tk.Entry(master)
        self.blacklist_entry.grid(row=0, column=1, padx=10, pady=5)

        self.add_blacklist_button = tk.Button(master, text="添加到黑名单", command=self.add_to_blacklist)
        self.add_blacklist_button.grid(row=0, column=2, padx=5, pady=5)

        self.blacklist_listbox = tk.Listbox(master, selectmode=tk.MULTIPLE)
        self.blacklist_listbox.grid(row=1, column=1, columnspan=1, padx=7, pady=3)

        self.delete_blacklist_button = tk.Button(master, text="批量删除", command=self.delete_blacklist)
        self.delete_blacklist_button.grid(row=1, column=2, pady=5)

        # 白名单部分
        self.whitelist_label = tk.Label(master, text="白名单:")
        self.whitelist_label.grid(row=3, column=0, sticky=tk.W)

        self.whitelist_entry = tk.Entry(master)
        self.whitelist_entry.grid(row=3, column=1, padx=10, pady=5)

        self.add_whitelist_button = tk.Button(master, text="添加到白名单", command=self.add_to_whitelist)
        self.add_whitelist_button.grid(row=3, column=2, padx=10, pady=5)

        self.whitelist_listbox = tk.Listbox(master, selectmode=tk.MULTIPLE)
        self.whitelist_listbox.grid(row=4, column=1, columnspan=1, padx=10, pady=5)

        self.delete_whitelist_button = tk.Button(master, text="批量删除", command=self.delete_whitelist)
        self.delete_whitelist_button.grid(row=4, column=2, pady=5)

        # 服务器信息显示部分
        self.server_info_label = tk.Label(master, text="服务器信息:")
        self.server_info_label.grid(row=0, column=3, sticky=tk.W, padx=10)

        self.server_info_text = tk.Text(master, width=40)
        self.server_info_text.grid(row=0, column=4, columnspan=2, rowspan=5, padx=10, pady=10, sticky=tk.N)

        # 服务器控制部分
        self.start_server_button = tk.Button(master, text="启动服务器", command=self.start_server)
        self.start_server_button.grid(row=4, column=4, padx=5, pady=5, sticky=tk.W)

        self.stop_server_button = tk.Button(master, text="关闭服务器", command=self.stop_server)
        self.stop_server_button.grid(row=4, column=5, padx=5, pady=5, sticky=tk.E)

        # 显示当前服务器的IP地址和端口号
        self.server_ip_label = tk.Label(master, text="服务器IP地址:")
        self.server_ip_label.grid(row=5, column=4, padx=10, pady=5)

        self.server_port_label = tk.Label(master, text="服务器端口号:")
        self.server_port_label.grid(row=5, column=5, padx=10, pady=5)

        # 初始化服务器状态
        self.server_running = False

    def enable_blacklist(self):
        self.blacklist_enabled = True
        self.whitelist_enabled = False
        self.enable_blacklist_button["state"] = tk.DISABLED
        self.enable_whitelist_button["state"] = tk.NORMAL
        self.enable_blacklist_button["text"] = "黑名单已启用"
        self.enable_whitelist_button["text"] = "启用白名单"
        self.server_info_text.insert(tk.END, "启用黑名单...\n")
        messagebox.showinfo("提示", "黑名单已启用")

        if self.server_running:  # 如果服务器在运行，重启服务器
            self.server_running = False
            self.thread_stop_event.set()  # 设置事件通知线程停止
            time.sleep(0.5)  # 等待0.5秒
            self.server_running = True
            self.thread_stop_event.clear()  # 重置事件
            self.server_thread = threading.Thread(
                target=run_server,
                args=(self.thread_stop_event, self.server_running, self.server_info_text, self.whitelist_enabled,
                      self.blacklist_enabled,
                      self.whitelist_listbox, self.blacklist_listbox, self.server_ip_label, self.server_port_label)
            )
            self.server_thread.start()

    def enable_whitelist(self):
        self.blacklist_enabled = False
        self.whitelist_enabled = True
        self.enable_blacklist_button["state"] = tk.NORMAL
        self.enable_whitelist_button["state"] = tk.DISABLED
        self.server_info_text.insert(tk.END, "启用白名单...\n")
        self.enable_whitelist_button["text"] = "白名单已启用"
        self.enable_blacklist_button["text"] = "启用黑名单"
        messagebox.showinfo("提示", "白名单已启用")

        if self.server_running:  # 如果服务器在运行，重启服务器
            self.server_running = False
            self.thread_stop_event.set()  # 设置事件通知线程停止
            time.sleep(0.5)  # 等待0.5秒
            self.server_running = True
            self.thread_stop_event.clear()  # 重置事件
            self.server_thread = threading.Thread(
                target=run_server,
                args=(self.thread_stop_event, self.server_running, self.server_info_text, self.whitelist_enabled,
                      self.blacklist_enabled,
                      self.whitelist_listbox, self.blacklist_listbox, self.server_ip_label, self.server_port_label)
            )
            self.server_thread.start()

    def add_to_blacklist(self):
        ip = self.blacklist_entry.get()
        if ip:
            self.blacklist_listbox.insert(tk.END, ip)
            self.blacklist_entry.delete(0, tk.END)

    def delete_blacklist(self):
        selected_indices = self.blacklist_listbox.curselection()
        if selected_indices:
            for index in reversed(selected_indices):
                self.blacklist_listbox.delete(index)

    def add_to_whitelist(self):
        ip = self.whitelist_entry.get()
        if ip:
            self.whitelist_listbox.insert(tk.END, ip)
            self.whitelist_entry.delete(0, tk.END)

    def delete_whitelist(self):
        selected_indices = self.whitelist_listbox.curselection()
        if selected_indices:
            for index in reversed(selected_indices):
                self.whitelist_listbox.delete(index)

    def start_server(self):
        if not self.server_running:
            self.server_running = True
            self.thread_stop_event.clear()  # 重置事件
            self.server_info_text.insert(tk.END, "启动服务器...\n")
            self.server_thread = threading.Thread(
                target=run_server,
                args=(self.thread_stop_event, self.server_running, self.server_info_text, self.whitelist_enabled, self.blacklist_enabled,
                      self.whitelist_listbox, self.blacklist_listbox, self.server_ip_label, self.server_port_label)
            )
            self.server_thread.start()

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            self.server_info_text.insert(tk.END, "关闭服务器...\n")
            self.thread_stop_event.set()  # 设置事件通知线程停止


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
