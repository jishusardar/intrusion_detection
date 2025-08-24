
# Real Time Intrusion Detection System

A Real-Time Intrusion Detection System is Used To Detect Any Outsider's Intrusion Inside a Network. This Tool Uses Python Library Pyshark to sniff the Data Packets of Protocol TCP and UDP from the Host Machine and Captures The Data Packets Within The Network and Outside The Network and Label Them Data Transmission Within the Network such as router Labeled as Own Network and Data Transmission Outside The Network is Labeled as Their Organization Name using python module requests by fetching api And render Them in an flask Based GUI for convinence.

## Installation
```bash
git clone https://github.com/jishusardar/intrusion_detection
cd intrusion_detection
pip3 install -r requirements.txt
python3 setup.py
python3 main.py
```
The Packet sniffing Started...

## File structure
You should have a file structure like this:
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
## The GUI Mode
for gui use 
```bash
python3 api_server.py
```
Starts The Flask-based Web Interface For Data Monitoring
## Demo
![Demo GUI](https://github.com/jishusardar/intrusion_detection/blob/main/Demo.png)
