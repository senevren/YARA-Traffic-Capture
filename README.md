# YARA rules with scapy for packet capture analysis
YARA is rule-based language designed for matching chunks of data. If you developed a rule for a particular malware variant that describes it well then that rule can be used to match instances of that traffic and provide alerts based off of that. 
We are using Scapy to handle the packet processing and so extracting the data we want to match and then using YARA rules to match the packet payloads predetermined in YARA syntax.
