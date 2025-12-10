from scapy.all import IP, UDP, Raw, send
import time

target_ip = "69.69.69.69"
target_port = 420

def send_string_data(ip, port, text):
    sz = len(text)
    for i in range(0,len(text), 100):
        byte_data = text[i:i+100]
        pkt = IP(dst=ip) / UDP(dport=port) / Raw(load=byte_data)
        send(pkt, verbose=0)
        print(f"Sent: ({i}/{sz})")

if __name__ == "__main__":
    send_string_data(target_ip, target_port, b"LOOK OVER HERE DINGUS!!!")

    with open("./flag.zip.gz", "rb") as file:
        send_string_data(target_ip, target_port, file.read())

