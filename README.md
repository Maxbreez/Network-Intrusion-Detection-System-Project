# Project Overview
This project implements a Network Intrusion Detection System (NIDS) with a user-friendly interface for capturing, analyzing, and filtering network packets. It can detect suspicious activities based on predefined rules and provide real-time alerts to the user. The system supports the analysis of TCP, HTTP, and HTTP2 streams, applies YARA rules to filter malicious patterns, and is capable of extracting and decoding objects from HTTP traffic.

# Prerequisites
Python 3.6+
Required Python packages (can be installed via requirements.txt):
PySimpleGUI
Scapy
YARA


# Modify File Paths
Log Files: Update the paths where log files will be stored.


# Change Network Interface Name
Network Interface: By default, the code monitors traffic on a specific network interface. You need to change the network interface to match your system. The interface can be auto-detected in the future, but for now, it must be manually set.

To change the network interface used for packet sniffing in the code, you need to modify the capiface variable and pass it to the scapy.sniff function. This way, the sniffing will happen on the selected network interface.

# How to Find Your Network Interface Name:
On Linux: Use the ifconfig or ip addr command to list network interfaces.
On Windows: Use the ipconfig command in the command prompt.


# Dependency Installation
Ensure all Python dependencies are installed:

# Other Requirements
Install Wireshark onto your machine