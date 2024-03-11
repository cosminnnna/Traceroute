# programul a fost scris folosind "https://alexanderell.is/posts/toy-traceroute/"
# si secvente de cod generate de chat.gpt

import socket
import struct
import time
import requests
import traceback


dest_port = 1  # portul destinatie pentru traceroute  (am dat un nr random)

# trimite un pachet catre o adresa IP data
# construieste si calculeaza checksum-ul pentru headerul ICMP
# seteaza Time-to-Live (TTL-ul) in headerul IP-ului
def send_icmp_request(icmp_sock, dest_addr, ttl):
    icmp_type = 8
    icmp_code = 0
    icmp_checksum = 0
    icmp_identifier = 6739  # o val random
    icmp_seq_number = 1  # o val random
    icmp_data = b"traceroute"

    # se constr header-ul ICMP - cu structura specifica
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number)

    # calculeaza checksum-ul ICMP-ului
    icmp_checksum = calcul_checksum(icmp_header + icmp_data)
    icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number)

    # seteaza TTL-u headerului de IP pentru socketul ICMP
    icmp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    # se trm ICMP Echo Request
    icmp_sock.sendto(icmp_header + icmp_data, (dest_addr, 0))

    # se retine mom trimiterii pachetului
    icmp_sent_time = time.time()

    return icmp_sent_time


# functia primeste un pachet IMCP Echo Replay si o adresa asociata
# extrage headerul ICMP din pachet
# return adresa sursa si mom la care a fost primit pachetul
def receive_icmp_reply(icmp_sock):
    try:
        # primeste pachetul ICMP Echo Reply + adresa sursa
        icmp_packet, addr = icmp_sock.recvfrom(63535)
        icmp_received_time = time.time()

        # se extrage headerul ICMP (8 octeti - ipul are fix 20)
        icmp_header = icmp_packet[20:28]
        icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_seq_number = struct.unpack("!BBHHH", icmp_header)

        return addr[0], icmp_received_time
    # in varianta asta se opreste
    except Exception as e:
        print("Socket timeout ", str(e))
        print(traceback.format_exc())
    # in varianta asta continua
    # except socket.timeout:
    #     return None, None




def traceroute(dest_addr, TTL, timeout):

    # socket RAW de citire a răspunsurilor ICMP
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_sock.settimeout(timeout)

    # socket de UDP
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

    # setam TTL in headerul de IP pentru socketul de UDP
    udp_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, TTL)

    print("Traceroute catre destinatia ", dest_addr, ":")

    for ttl in range(1, TTL + 1):
        print(ttl, "   ")

        # se trimite pachetul ICMP Echo Request
        send_icmp_request(icmp_sock, dest_addr, ttl)

        # se trimite un mesaj catre un tuplu (IP, port)
        # (mesaj UDP catre destinatie pentru a primi un mesaj ICMP TTL Exceeded)
        udp_sock.sendto(b"salut :)", (dest_addr, dest_port))

        # se asteapta un mesaj ICMP Echo Reply/ mesaj TTL Exceeded
        icmp_sock.settimeout(timeout)
        addr, icmp_received_time = receive_icmp_reply(icmp_sock)

        # utiliza ipinfo.ro care furnizeaza inf despre locatia IP-ului
        response = requests.get(f"https://ipinfo.io/{addr}/json")
        data = response.json()

        if addr:
            print(addr)
            if "country" in data:
                print("Informații despre locație:")
            else:
                print("Nu s-a gasit informatii pentru adresa IP data.")
            if "city" in data:
                print("Oraș:", data["city"])

            if "region" in data:
                print("Regiune:", data["region"])

            if "country" in data:
                print("Țară:", data["country"])

            print("\n")
        else:
            # daca in timpul dat (timeout) nu s-a primit un raspuns ICMP
            print("*\n")

        if addr == dest_addr:
            break

    icmp_sock.close()
    udp_sock.close()


# suma de control pentru un buffer de date
def calcul_checksum(data):
    checksum = 0

    if len(data) % 2 == 1:
        data += b"\x00"

    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    checksum = ~checksum & 0xffff

    return checksum


if __name__ == "__main__":
    ok = int(input("Tasteaza '0' pentru a introduce site-ul destinatie sau '1' pentru adresa IP destinatie:"))
    dest_addr = ""
    if ok == 0:
        domain = input("Site destinatie: ")
        dest_addr = socket.gethostbyname(domain)
    else:
        dest_addr = input("IP destinatie: ")

    ttl = int(input("TTL: "))

    # setam timeout in cazul in care socketul ICMP la apelul recvfrom nu primeste nimic in buffer
    timeout = int(input("timeout: "))

    traceroute(dest_addr, ttl, timeout)