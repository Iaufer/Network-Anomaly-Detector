import sys, argparse
sys.path.append('/home/laufer/.local/lib/python3.10/site-packages')

from scapy.all import  sniff, wrpcap
from datetime import timedelta


def packet_callback(packet):
    print("ARP Packet Detected:")
    print(packet.summary())

    wrpcap('info.pcap', packet, append=True)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Сбор данных о сетевом трафике.')
    parser.add_argument('--period', type=int, default=24, help='Период сбора в часах')

    return parser.parse_args()


def main():
    args = parse_arguments()

    collection_period = timedelta(hours=args.period)

    print(f'Период сбора данных: {collection_period}')
    sniff(prn=packet_callback, store=0)


if __name__ == "__main__":
    main()


