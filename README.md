
# Real Time Intrusion Detection System

A Real-Time Intrusion Detection System is Used To Detect Any Outsider's Intrusion Inside a Network. This Tool Uses wireshark and Python Library Pyshark to sniff the Data Packets of Protocol TCP and UDP from the Host Machine and Captures The Data Packets Within The Network and Outside The Network and Label Them Data Transmission Within the Network such as router Labeled as Own Network and Data Transmission Outside The Network is Labeled as Their Organization Name And render Them in an flask Based GUI for convinence.
🔍 Monitors live packet flows with PyShark and Wireshark integration
📊 Analyses TCP/UDP protocols with detailed logs on host machines
🏷️ Labels traffic behaviour - internal communication versus external traffic
🌐 Performs API calls for the analysis of remote IPs to identify the destination organisations or the source organisation.
🖥️ Has a web GUI for ease of monitoring and management.
The challenges we face: Network intruders manipulate data packets without our knowledge for their own purposes. 
The solution we have: This system exists to give you real-time visibility into your network's packet flow, so suspicious activity may be recognised before it becomes a security issue.
Currently, it is configured for macOS/Linux network interfaces only.
🔎 The script automatically sets up the tools for the Host Machine by simply running setup.py. The script itself fetches the user's IP and available port on the Host Machine to create and configure the .env file in the project directory.
❇️ All the Python Modules are handled by the requirements.txt
🤖 The main.py is the file that fetches the network interface using netifaces, sniffs the Data Packets in real Time, and labels them within the network as Own Network and Outside Network, as Organization Name by using an asynchronous function to call api using httpx, and Filters The Data Packets by TCP and UDP Protocols and Send Report To The Host Machine.
 📁 The api_server.py renders Data That Is acquired by the class Data_Packet in the webpage On The Host Machine IP and Port that is already configured by setup.py.

## Requirements
### Wireshark
For Macos
```bash
brew install wireshark
```
For Debian(Linux)
```bash
sudo apt-get install wireshark
```
## Installation
### For Macos/Linux
```bash
git clone https://github.com/jishusardar/intrusion_detection
cd intrusion_detection
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
python3 setup.py
```
## Start GUI Mode
```bash
python3 api_server.py
```
Starts The Flask-based Web Interface For Data Monitoring

## Start Packet Monitoring
In another Terminal Tab, Start Packet Monitoring
```bash
python3 main.py
```
## File structure
you should have a file structure like this:
```bash
intrusion_detection/
├── api_server.py
├── main.py
├── setup.py
|── .env
├── requirements.txt
└── templates/
    └── index.html
```
## Demo

![Demo GUI](https://github.com/jishusardar/intrusion_detection/blob/main/Demo.png)

## Demo Video:
https://youtu.be/JNrdr-AJxAY

