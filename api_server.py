from flask import Flask, request, jsonify, render_template
import logging
import json
from dotenv import load_dotenv
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# Store received data in memory
received_data = []

@app.route('/api/', methods=['POST'])
def receive_packet():
    try:
        data = request.get_json(force=True)
        received_data.append(data)  # Store incoming JSON
        logging.info(f"Received packet data:\n{json.dumps(data, indent=2)}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        logging.error(f"Error: {e}")
        return jsonify({"error": str(e)}), 500

# 👉 Show data on the index page
@app.route('/', methods=['GET'])
def index():
    return render_template("index.html", data=received_data)

if __name__ == '__main__':
    load_dotenv()
    port = int(os.getenv('my_port', 5000))
    app.run(host='0.0.0.0', port=port)