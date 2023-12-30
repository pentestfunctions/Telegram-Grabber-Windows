import os
import subprocess
import requests
import socket
import ipaddress
import pyshark

# Telegram list of excluded IP ranges
EXCLUDED_NETWORKS = [
    '91.108.13.0/24', '149.154.160.0/21', '149.154.160.0/22',
    '149.154.160.0/23', '149.154.162.0/23', '149.154.164.0/22',
    '149.154.164.0/23', '149.154.166.0/23', '149.154.168.0/22',
    '149.154.172.0/22', '185.76.151.0/24', '91.105.192.0/23',
    '91.108.12.0/22', '91.108.16.0/22', '91.108.20.0/22',
    '91.108.4.0/22', '91.108.56.0/22', '91.108.56.0/23',
    '91.108.58.0/23', '91.108.8.0/22', '95.161.64.0/20'
]

def check_tshark():
    tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe"
    return os.path.exists(tshark_path)

def list_interfaces():
    tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe"
    result = subprocess.run([tshark_path, "-D"], capture_output=True, text=True)
    return result.stdout.splitlines()

def select_interface(interfaces):
    print("Available network interfaces:")
    for idx, interface in enumerate(interfaces, start=1):
        print(f"{idx}. {interface}")

    while True:
        choice = input("Select an interface to use (number): ")
        try:
            choice = int(choice)
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1].split('.')[0]
            else:
                print("Invalid choice. Please enter a valid number.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    return None  # In case of an error, you can return None or handle it as needed

def get_whois_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
        print(f"[!] Error fetching WHOIS data for {ip}: Invalid response")
    except Exception as e:
        print(f"[!] Error fetching WHOIS data for {ip}: {e}")
    return None

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def is_excluded_ip(ip):
    try:
        ip_addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(ip_addr in ipaddress.ip_network(network) for network in EXCLUDED_NETWORKS)

def process_stun_packets(interface):
    print(f"Running stun capture now to try and find the target.")
    print(f"This could take up to 30 seconds while calling")
    print(f"Call your target now:")

    checked_ips = set()  # Set to keep track of IPs that have been checked

    try:
        cap = pyshark.LiveCapture(interface=interface, display_filter="stun")
        for packet in cap.sniff_continuously(packet_count=999999):  # Adjust packet count as needed
            if hasattr(packet, 'ip'):
                dst_ip = packet.ip.dst
                if dst_ip in checked_ips or is_excluded_ip(dst_ip):
                    continue

                # Add the IP to the set of checked IPs before WHOIS retrieval
                checked_ips.add(dst_ip)

                dst_info = get_whois_info(dst_ip)
                if dst_info:  # Check if WHOIS data was successfully retrieved for destination IP
                    if hasattr(packet, 'stun'):
                        xor_mapped_address = packet.stun.get_field_value('stun.att.ipv4')
                        print(f"[+] Found STUN packet: Destination IP -> {dst_ip}. XOR Mapped Address: {xor_mapped_address}")
                        display_whois_info(dst_info)
                        break  # Stop processing after successful WHOIS data retrieval for destination IP

    except Exception as e:
        print(f"Error processing packets: {e}")

def display_whois_info(data):
    if not data:
        return

    print("\n[WHOIS Information]")
    for key in ['query', 'country', 'countryCode', 'region', 'regionName', 'city', 'zip', 'lat', 'lon', 'timezone', 'isp', 'org', 'as']:
        print(f"{key}: {data.get(key, 'N/A')}")

def main():
    try:
        if not check_tshark():
            print("tshark is not available. Please ensure Wireshark is installed.")
            print(f"During the installation process, ensure it goes to the default location and enable tshark.")
            print(f"https://www.wireshark.org/download.html")
            return

        interfaces = list_interfaces()
        if not interfaces:
            print("No network interfaces available.")
            return

        selected_interface = select_interface(interfaces)
        process_stun_packets(selected_interface)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
