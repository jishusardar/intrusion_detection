
# Real Time Intrusion Detection System

A Real-Time Intrusion Detection System is Used To Detect Any Outsider's Intrusion Inside a Network. This Tool Uses wireshark and Python Library Pyshark to sniff the Data Packets of Protocol TCP and UDP from the Host Machine and Captures The Data Packets Within The Network and Outside The Network and Label Them Data Transmission Within the Network such as router Labeled as Own Network and Data Transmission Outside The Network is Labeled as Their Organization Name And render Them in an flask Based GUI for convinence.

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
python3 main.py
```

## The GUI Mode
Packet Sniffing Started and then
In Another Terminal Tab
```bash
python3 api_server.py
```
Starts The Flask-based Web Interface For Data Monitoring
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
