from flask import Flask, request, jsonify
import subprocess
import os
import time

app = Flask(__name__)

# Shared secret password
SHARED_SECRET = "C0RT4N4"

# Function to check authorization
def check_authorization(request):
    auth_header = request.headers.get("Authorization")
    if auth_header == SHARED_SECRET:
        return True
    return False

# Function to get the current WiFi status (Online/Offline)
def get_wifi_status():
    try:
        result = subprocess.check_output(['iwgetid']).decode('utf-8').strip()
        if result:
            return {"status": "Online", "network": result.split('ESSID:\"')[-1].strip('\"')}
        else:
            return {"status": "Offline"}
    except subprocess.CalledProcessError:
        return {"status": "Offline"}

# Function to get detailed connection information (SSID, Signal Strength)
def get_connection_info():
    try:
        # Get WiFi status
        status_result = subprocess.check_output(['iwgetid']).decode('utf-8').strip()
        status = "Online" if status_result else "Offline"

        # Initialize variables
        ssid = None
        signal_strength = None
        ip_address = None

        if status == "Online":
            # Get WiFi connection details
            result = subprocess.check_output(['iwconfig', 'wlan0']).decode('utf-8')
            for line in result.splitlines():
                if "ESSID" in line:
                    ssid = line.split('ESSID:')[-1].strip('"')
                elif "Signal level" in line:
                    signal_strength = line.split('Signal level=')[-1].split(' ')[0]

            # Get IP address
            ip_result = subprocess.check_output(['hostname', '-I']).decode('utf-8').strip()
            ip_address = ip_result.split(' ')[0] if ip_result else None

        return {"status": status, "ssid": ssid, "signal_strength": signal_strength, "ip_address": ip_address}
    except subprocess.CalledProcessError:
        return {"error": "Unable to retrieve connection information"}

# Function to disconnect from the current WiFi network
def disconnect_from_network():
    try:
        subprocess.call(['sudo', 'ifconfig', 'wlan0', 'down'])
        subprocess.call(['sudo', 'ifconfig', 'wlan0', 'up'])
        return {"message": "Disconnected from current network"}
    except Exception as e:
        return {"error": str(e)}

@app.route('/status', methods=['GET'])
def status():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_wifi_status())

@app.route('/connection_info', methods=['GET'])
def connection_info():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_connection_info())

@app.route('/scan', methods=['GET'])
def scan():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    try:
        networks = subprocess.check_output(['sudo', 'iwlist', 'wlan0', 'scan']).decode('utf-8')
        ssid_list = []
        for line in networks.split('\n'):
            if "ESSID:" in line:
                ssid = line.split('ESSID:')[-1].strip('\"')
                if ssid:
                    ssid_list.append(ssid)
        return jsonify({"networks": ssid_list})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route('/connect', methods=['POST'])
def connect():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    ssid = data.get('ssid')
    password = data.get('password')

    if not ssid:
        return jsonify({"error": "SSID is required"}), 400

    try:
        os.system("nmcli device disconnect wlan0")
        os.system("sudo dhclient -r wlan0")
        time.sleep(2)

        with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'r') as file:
            lines = file.readlines()
        with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'w') as file:
            file.writelines([line for line in lines if "network=" not in line])

        config = f'network={{\n    ssid=\"{ssid}\"\n    psk=\"{password}\"\n}}'
        with open('/etc/wpa_supplicant/wpa_supplicant.conf', 'a') as file:
            file.write(config)

        os.system("sudo ifdown wlan0")
        time.sleep(1)
        os.system("sudo ifup wlan0")
        os.system("sudo dhclient wlan0")

        result = os.popen(f"nmcli dev wifi connect '{ssid}' password '{password}'").read()
        with open("/tmp/wifi_log.txt", "a") as log:
            log.write(f"Attempted connection to SSID: {ssid}\n")
            log.write(result + "\n")

        return jsonify({"message": "Connection attempt in progress"})

    except Exception as e:
        with open("/tmp/wifi_log.txt", "a") as log:
            log.write(f"Connection error: {str(e)}\n")
        return jsonify({"error": str(e)})

@app.route('/disconnect', methods=['GET'])
def disconnect():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(disconnect_from_network())

# Bluetooth scanning function
def scan_bluetooth_devices():
    try:
        subprocess.call(['timeout', '10s', 'bluetoothctl', 'scan', 'on'])
        time.sleep(5)
        subprocess.call(['bluetoothctl', 'scan', 'off'])
        devices = subprocess.check_output(['bluetoothctl', 'devices']).decode('utf-8')

        device_list = []
        for line in devices.splitlines():
            if "Device" in line:
                parts = line.split(' ')
                mac_address = parts[1]
                device_name = ' '.join(parts[2:])
                device_list.append({'mac_address': mac_address, 'device_name': device_name})

        return {"devices": device_list}
    except subprocess.CalledProcessError as e:
        return {"error": "Bluetooth scan failed: {}".format(str(e))}
    except Exception as e:
        return {"error": "An error occurred during Bluetooth scanning: {}".format(str(e))}

def connect_bluetooth_device(mac_address):
    try:
        devices = subprocess.check_output(['bluetoothctl', 'devices']).decode('utf-8')
        if mac_address not in devices:
            return {"error": f"Device {mac_address} not available in the device list."}

        subprocess.call(['bluetoothctl', 'discoverable', 'on'])
        time.sleep(1)
        result = subprocess.check_output(['bluetoothctl', 'connect', mac_address]).decode('utf-8')

        if "Connection successful" in result:
            return {"message": f"Connected to {mac_address}"}
        else:
            return {"error": f"Failed to connect to {mac_address}: {result.strip()}"}
        
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to connect to {mac_address}: {str(e)}"}
    except Exception as e:
        return {"error": f"An error occurred while connecting to Bluetooth device: {str(e)}"}

@app.route('/bluetooth_scan', methods=['GET'])
def bluetooth_scan():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(scan_bluetooth_devices())

@app.route('/connect_bluetooth', methods=['POST'])
def connect_bluetooth():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    mac_address = data.get('mac_address')

    if not mac_address:
        return jsonify({"error": "MAC Address is required"}), 400

    return jsonify(connect_bluetooth_device(mac_address))

# XLink & insigniaDNS section
def start_xlinkkai():
    try:
        subprocess.call(['sudo', 'systemctl', 'start', 'KaiEngine'])
        return {"message": "Starting XLink Kai!"}
    except Exception as e:
        return {"error": str(e)}

def stop_xlinkkai():
    try:
        subprocess.call(['sudo', 'systemctl', 'stop', 'KaiEngine'])
        return {"message": "Stopping XLink Kai!"}
    except Exception as e:
        return {"error": str(e)}

def enable_xlinkkai():
    try:
        subprocess.call(['sudo', 'systemctl', 'enable', 'KaiEngine'])
        return {"message": "Enabling XLink Kai!"}
    except Exception as e:
        return {"error": str(e)}

def disable_xlinkkai():
    try:
        subprocess.call(['sudo', 'systemctl', 'disable', 'KaiEngine'])
        return {"message": "Disabling XLink Kai!"}
    except Exception as e:
        return {"error": str(e)}

def start_insigniadns():
    try:
        subprocess.call(['sudo', 'systemctl', 'start', 'insigniaDNS'])
        return {"message": "Starting insigniaDNS!"}
    except Exception as e:
        return {"error": str(e)}

def stop_insigniadns():
    try:
        subprocess.call(['sudo', 'systemctl', 'stop', 'insigniaDNS'])
        return {"message": "Stopping insigniaDNS!"}
    except Exception as e:
        return {"error": str(e)}

def enable_insigniadns():
    try:
        subprocess.call(['sudo', 'systemctl', 'enable', 'insigniaDNS'])
        return {"message": "Enabling insigniaDNS!"}
    except Exception as e:
        return {"error": str(e)}

def disable_insigniadns():
    try:
        subprocess.call(['sudo', 'systemctl', 'disable', 'insigniaDNS'])
        return {"message": "Disabling insigniaDNS!"}
    except Exception as e:
        return {"error": str(e)}

def start_xbdStats():
    try:
        subprocess.call(['sudo', 'systemctl', 'start', 'xbdStats'])
        return {"message": "Starting xbdStats!"}
    except Exception as e:
        return {"error": str(e)}

def stop_xbdStats():
    try:
        subprocess.call(['sudo', 'systemctl', 'stop', 'xbdStats'])
        return {"message": "Stopping xbdStats!"}
    except Exception as e:
        return {"error": str(e)}

def enable_xbdStats():
    try:
        subprocess.call(['sudo', 'systemctl', 'enable', 'xbdStats'])
        return {"message": "Enabling xbdStats!"}
    except Exception as e:
        return {"error": str(e)}

def disable_xbdStats():
    try:
        subprocess.call(['sudo', 'systemctl', 'disable', 'xbdStats'])
        return {"message": "Disabling xbdStats!"}
    except Exception as e:
        return {"error": str(e)}

def start_smb():
    try:
        subprocess.call(['sudo', 'systemctl', 'start', 'smb'])
        return {"message": "Starting SMB server!"}
    except Exception as e:
        return {"error": str(e)}

def stop_smb():
    try:
        subprocess.call(['sudo', 'systemctl', 'stop', 'smb'])
        return {"message": "Stopping SMB server!"}
    except Exception as e:
        return {"error": str(e)}

def enable_smb():
    try:
        subprocess.call(['sudo', 'systemctl', 'enable', 'smb'])
        return {"message": "Enabling SMB server!"}
    except Exception as e:
        return {"error": str(e)}

def disable_smb():
    try:
        subprocess.call(['sudo', 'systemctl', 'disable', 'smb'])
        return {"message": "Disabling SMB server!"}
    except Exception as e:
        return {"error": str(e)}

def start_ftp():
    try:
        subprocess.call(['sudo', 'systemctl', 'start', 'ftp'])
        return {"message": "Starting FTP server!"}
    except Exception as e:
        return {"error": str(e)}

def stop_ftp():
    try:
        subprocess.call(['sudo', 'systemctl', 'stop', 'ftp'])
        return {"message": "Stopping FTP server!"}
    except Exception as e:
        return {"error": str(e)}

def enable_ftp():
    try:
        subprocess.call(['sudo', 'systemctl', 'enable', 'ftp'])
        return {"message": "Enabling FTP server!"}
    except Exception as e:
        return {"error": str(e)}

def disable_ftp():
    try:
        subprocess.call(['sudo', 'systemctl', 'disable', 'ftp'])
        return {"message": "Disabling FTP server!"}
    except Exception as e:
        return {"error": str(e)}

# XLink, insigniaDNS xbdStats, SMB and FTP App Routes

@app.route('/startxlinkkai', methods=['GET'])
def startxlinkkai():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_xlinkkai())

@app.route('/stopxlinkkai', methods=['GET'])
def stopxlinkkai():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(stop_xlinkkai())

@app.route('/enablexlinkkai', methods=['GET'])
def enablexlinkkai():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(enable_xlinkkai())

@app.route('/disablexlinkkai', methods=['GET'])
def disablexlinkkai():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(disable_xlinkkai())

@app.route('/startinsigniadns', methods=['GET'])
def startinsigniadns():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_insigniadns())

@app.route('/stopinsigniadns', methods=['GET'])
def stopinsigniadns():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(stop_insigniadns())

@app.route('/enableinsigniadns', methods=['GET'])
def enableinsigniadns():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(enable_insigniadns())

@app.route('/disableinsigniadns', methods=['GET'])
def disableinsigniadns():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(disable_insigniadns())

@app.route('/startxbdstats', methods=['GET'])
def startxbdstats():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_xbdStats())

@app.route('/stopxbdstats', methods=['GET'])
def stopxbdstats():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(stop_xbdStats())

@app.route('/enablexbdstats', methods=['GET'])
def enablexbdstats():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(enable_xbdStats())

@app.route('/disablexbdstats', methods=['GET'])
def disablexbdstats():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(disable_xbdStats())

@app.route('/startxbdstats', methods=['GET'])
def startsmb():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_smb())

@app.route('/startsmb', methods=['GET'])
def stopsmb():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_smb())

@app.route('/stopsmb', methods=['GET'])
def stopsmb():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(stop_smb())

@app.route('/startftp', methods=['GET'])
def stopsmb():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(start_ftp())

@app.route('/stopftp', methods=['GET'])
def stopsmb():
    if not check_authorization(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(stop_ftp())

# OUT OF DATE - NEED TO FIX!
@app.route('/', methods=['GET'])
def home():
    return """
    Welcome to the Raspberry Pi WiFi Manager API. Choose an option:
    1. /status - Get Connection Status (Online/Offline)
    2. /connection_info - Get Connection Information (SSID, Signal Strength)
    3. /scan - Scan for available WiFi Networks
    4. /connect - Connect to a new WiFi Network (POST with SSID and Password)
    5. /disconnect - Disconnect from current WiFi Network
    6. /bluetooth_scan - Scan for Bluetooth Devices
    7. /connect_bluetooth - Connect to a Bluetooth Device (POST with MAC Address)
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
