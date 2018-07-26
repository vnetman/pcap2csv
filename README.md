# pcap2csv
Use PyShark and scapy to read fields from a pcap file and populate a CSV

Script to extract specific pieces of information from a pcap file and
render into a csv file.

    Usage: <program name> --pcap <input pcap file> --csv <output pcap file>

Each packet in the pcap is rendered into one row of the csv file.
The specific items to extract, and the order in which they are rendered
in the csv are hard-coded in the script, in the 'render_csv_row' function.
Also note that the separators in the csv are '|' characters, not commas.

This script uses *both* PyShark (https://kiminewt.github.io/pyshark/) and
Scapy to do its work. PyShark because we want to leverage tshark's powerful
protocol decoding ability to generate the "textual description" field of
the CSV (like "Standard query 0xf3de A www.cisco.com", "Client Hello" etc.), 
and Scapy because at the same time we want to access the "payload"
portion of the packet (PyShark seems to be unable to provide this).
