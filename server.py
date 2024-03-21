import socket
import threading
import tkinter as tk
from SimpleFirewall import SimpleFirewall
from getLocal import get_local_ip


def handle_client(client_socket, server_info_text, addr):  # 处理客户端信息

    request = client_socket.recv(1024).decode("utf-8")
    server_info_text.insert(tk.END, f"已接受来自 {addr[0]}:{addr[1]} 的消息：{request}\n")
    response = f"Hello from server! You sent: {request}"

    client_socket.send(response.encode("utf-8"))
    client_socket.close()


def run_server(thread_stop_event, server_running, server_info_text, whitelist_enabled, blacklist_enabled,
               whitelist_listbox,  # 运行服务器
               blacklist_listbox, server_ip_label, server_port_label):
    firewall = SimpleFirewall()
    print("Server thread has started.")
    # 添加黑名单或白名单中的IP，根据启用的名单类型
    if blacklist_enabled:
        for ip in blacklist_listbox.get(0, tk.END):
            firewall.add_to_blacklist(ip)
    elif whitelist_enabled:
        for ip in whitelist_listbox.get(0, tk.END):
            firewall.add_to_whitelist(ip)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 8888))
    server.listen(5)
    server.settimeout(0.5)  # 设置超时时间，单位为秒

    server_ip_label.config(text=f"服务器IP地址: {get_local_ip()}")  # 获取服务器IP
    server_port_label.config(text="服务器端口号: 8888")

    while not thread_stop_event.is_set():
        try:
            client_socket, addr = server.accept()
            # 检查客户端IP是否在黑名单或白名单中
            client_ip = addr[0]
            if blacklist_enabled and client_ip in firewall.blacklist:
                server_info_text.insert(tk.END, f"已拒绝来自 {client_ip} 的连接 (在黑名单中)\n")
                client_socket.close()
                continue
            elif whitelist_enabled and client_ip not in firewall.whitelist:
                server_info_text.insert(tk.END, f"已拒绝来自 {client_ip} 的连接 (不在白名单中)\n")
                client_socket.close()
                continue

            client_handler = threading.Thread(target=handle_client, args=(client_socket, server_info_text, addr))
            client_handler.start()

        except socket.timeout:
            pass  # 超时时什么也不做，继续循环检查 thread_stop_event

        except Exception as e:
            server_info_text.insert(tk.END, f"Error: {str(e)}\n")
            break
    print("Server thread is stopping.")
    server.close()  # 关闭服务器的 socket
