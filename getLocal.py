import socket
#获取本地ip
def get_local_ip():
    try:
        # 创建一个 UDP 套接字
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 连接到外部服务器（不需要连接到外部服务器，只是为了获取本地 IP 地址）
        s.connect(("8.8.8.8", 80))
        # 获取本地 IP 地址
        local_ip = s.getsockname()[0]
    except Exception as e:
        print(f"Error getting local IP: {str(e)}")
        local_ip = "Unknown"
    finally:
        s.close()
    return local_ip