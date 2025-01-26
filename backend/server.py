from passlib.hash import bcrypt
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from pymongo.errors import ConnectionFailure
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from datetime import timedelta

from unificontrol import UnifiClient

import time
from ciscomeapi import CiscoME
import json
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) 

jwt = JWTManager(app)
secret_key = os.urandom(24)
app.config['JWT_SECRET_KEY'] = secret_key
USER_DATA = {
    "username": "rmocanu001",
    "password": hashlib.sha256("pass".encode()).hexdigest() 
}

uri = "mongodb+srv://mongodb0.example.com/admin"
client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)


def log_command(command, result, user):
    db = client.get_database("licenta")
    logs_collection = db.logs
    log_entry = {
        "command": command,
        "result": result,
        "user": user,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    logs_collection.insert_one(log_entry)

@app.route('/locations', methods=['GET', 'POST'])
@jwt_required()
def locations():

    db = client.get_database("licenta")
    locations_collection = db.locations
    
    if request.method == 'POST':
        data = request.json
        locations_collection.insert_one(data)
        return jsonify(message="Location added"), 201
    
    elif request.method == 'GET':
        locations = list(locations_collection.find({}, {'_id': 0}))
        return jsonify(locations)

@app.route('/locations/<location_ip>', methods=['DELETE'])
@jwt_required()
def delete_location(location_ip):
    db = client.get_database("licenta")
    locations_collection = db.locations

    if not location_ip:
        return jsonify({"message": "IP address is not provided!"}), 400

    location = locations_collection.find_one({"ip": location_ip})
    if not location:
        return jsonify({"message": "Location not found!"}), 404

    locations_collection.delete_one({"ip": location_ip})
    log_command(f"delete location {location_ip}", "success", get_jwt_identity())
    return jsonify(message="Location deleted"), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    user = USER_DATA if username == USER_DATA["username"] else None

    if not user:
        return jsonify({"message": "Invalid username or password!"}), 401

    if hashlib.sha256(password.encode()).hexdigest() == USER_DATA['password']:
        access_token = create_access_token(identity=str(user['username']), expires_delta=timedelta(days=7))
        return jsonify({"token": access_token}), 200
    else:
        return jsonify({"message": "Invalid username or password!"}), 401

def fetch_cisco_info(ip):
    try:
        me = CiscoME(host=ip, username="rmocanu001", password='pass')
        info = me.system_information()
        json_info = json.dumps(info, indent=4)
        return json_info, 200
    except Exception as e:
        print(f"Error connecting to Cisco device: {e}")
        return jsonify({"message": "Failed to connect to Cisco device"}), 500

@app.route('/access_points_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def access_points_cisco(location_ip):
    try:
        me = CiscoME(host=location_ip, username="rmocanu001", password='pass')
        info = me.aps_data()
        json_info = json.dumps(info, indent=4)
        log_command(f"access_points_cisco {location_ip}", "success", get_jwt_identity())
        return json_info, 200
    except Exception as e:
        print(f"Error connecting to Cisco device: {e}")
        return jsonify({"message": "Failed to connect to Cisco device"}), 500

@app.route('/device_info_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def device_info_cisco(location_ip):
    db = client.get_database("licenta")
    locations_collection = db.locations
    
    if not location_ip:
        return jsonify({"message": "IP address is not provided!"}), 400

    location = locations_collection.find_one({"ip": location_ip})
    if not location:
        return jsonify({"message": "Location not found!"}), 404

    log_command(f"device_info_cisco {location_ip}", "success", get_jwt_identity())
    return fetch_cisco_info(location_ip)

def format_uptime(seconds):
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days}d {hours}h {minutes}m {seconds}s"

def get_unifi_client():
    controller_url = 'localhost'
    username = 'rmocanu001'
    password = 'pass'
    site_id = 'default'
    client = UnifiClient(host=controller_url, username=username, password=password, site=site_id)
    client.login()
    return client

@app.route('/device_info_ubiquity', methods=['GET'])
@jwt_required()
def get_device_info():
    try:
        client = get_unifi_client()
        devices = client.list_devices()
        if not devices:
            return jsonify({"error": "No devices found"}), 404

        device_info = devices[0]

        uptime_seconds = device_info.get('uptime', 'N/A')
        uptime = format_uptime(uptime_seconds) if uptime_seconds != 'N/A' else 'N/A'

        wlans = client.list_wlanconf()
        wlan_list = []
        for wlan in wlans:
            wlan_info = {
                'WLAN Identifier': wlan.get('_id', 'N/A'),
                'Network Name (SSID)': wlan.get('name', 'N/A'),
                'Radio Policy': ', '.join(wlan.get('wlan_bands', [])),
                'Status': 'Enabled' if wlan.get('enabled', False) else 'Disabled',
                'Security': wlan.get('wpa_mode', 'N/A')
            }
            wlan_list.append(wlan_info)

        response = {
            'prodid': device_info.get('model', 'N/A'),
            'serial': device_info.get('serial', 'N/A'),
            'version': device_info.get('version', 'N/A'),
            'uptime': uptime,
            'ipaddr': device_info.get('ip', 'N/A'),
            'memory': device_info.get('mem_total', 'N/A'),
            'wlanCount': len(wlan_list),
            'activeAPCount': sum(1 for ap in devices if ap['type'] == 'uap' and ap['state'] == 0),
            'a_clients': device_info.get('num_sta', 0),
            'wlan_list': wlan_list
        }

        log_command("device_info_ubiquity", "success", get_jwt_identity())
        return jsonify(response)
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/get_logs_ubiquity/<ip>', methods=['GET'])
@jwt_required()
def get_logs_ubiquity(ip):
    try:
        client = get_unifi_client()
        logs = client.stat_daily_aps()
        log_command(f"get_logs_ubiquity {ip}", "success", get_jwt_identity())
        return jsonify({"logs": "Feched logs daily"}), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/update_ubiquity_device/<mac>', methods=['POST'])
@jwt_required()
def update_ubiquity_device(mac):
    try:
        client = get_unifi_client()
        client.upgrade_device(mac)
        log_command(f"update_ubiquity_device {mac}", "success", get_jwt_identity())
        return jsonify({"message": "Ubiquiti device updated successfully"}), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/access_points_ubiquity/<ip>', methods=['GET'])
@jwt_required()
def access_points_ubiquity(ip):
    try:
        client = get_unifi_client()
        devices = client.list_devices()
        aps = [device for device in devices if device['type'] == 'uap']
        ap_list = []
        for ap in aps:
            ap_info = {
                'id': ap.get('serial', 'N/A'),
                'name': ap.get('name', 'N/A'),
                'ip': ap.get('ip', 'N/A'),
                'admin': 'Active' if ap.get('state', 0) == 1 else 'Inactive',
                'uptime': format_uptime(ap.get('uptime', 'N/A')),
                'model': ap.get('model', 'N/A'),
                'loc': ap.get('locating', 'N/A'),
                'mac': ap.get('mac', 'N/A')
            }
            ap_list.append(ap_info)
        log_command(f"access_points_ubiquity {ip}", "success", get_jwt_identity())
        return jsonify({"data": ap_list})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/reset_ap_ubiquity/<ip>/<mac>', methods=['POST'])
@jwt_required()
def reset_ap_ubiquity(ip, mac):
    try:
        client = get_unifi_client()
        result = client.restart_ap(mac)
        log_command(f"reset_ap_ubiquity {ip} {mac}", "success", get_jwt_identity())
        if result:
            return jsonify({"message": "Access Point reset successfully"}), 200
        else:
            return jsonify({"message": "Failed to reset Access Point"}), 500
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/clients_ubiquity', methods=['GET'])
@jwt_required()
def clients_ubiquity():
    try:
        client = get_unifi_client()
        clients = client.list_clients()
        client_list = []
        for cl in clients:
            client_info = {
                'id': cl.get('mac', 'N/A'),
                'name': cl.get('hostname', 'N/A'),
                'details': {
                    'ap': cl.get('ap_mac', 'N/A'),
                    'ipv4': cl.get('ip', 'N/A'),
                    'ipv6': cl.get('ipv6', 'N/A'),
                    'signalStrength': cl.get('signal', 'N/A'),
                    'signalQuality': cl.get('rssi', 'N/A'),
                    'connectionSpeed': cl.get('tx_rate', 'N/A'),
                    'frequency': cl.get('frequency', 'N/A'),
                    'capability': cl.get('capability', 'N/A'),
                    'deviceType': cl.get('oui', 'N/A'),
                    'ssid': cl.get('essid', 'N/A'),
                    'apGroup': cl.get('ap_group_name', 'N/A'),
                    'bytesTotal': cl.get('bytes', 'N/A'),
                }
            }
            client_list.append(client_info)
        log_command("clients_ubiquity", "success", get_jwt_identity())
        return jsonify({"data": client_list})
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/clients_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def clients_cisco(location_ip):
    try:
        me = CiscoME(host=location_ip, username="rmocanu001", password='pass')
        info = me.client_table()
        json_info = json.dumps(info, indent=4)
        log_command(f"clients_cisco {location_ip}", "success", get_jwt_identity())
        return json_info, 200
    except Exception as e:
        print(f"Error connecting to Cisco device: {e}")
        return jsonify({"message": "Failed to connect to Cisco device"}), 500

@app.route('/reset_ap_cisco/<location_ip>/<mac>', methods=['POST'])
@jwt_required()
def reset_ap_cisco(location_ip, mac):
    try:
        me = CiscoME(host=location_ip, username="rmocanu001", password='pass')
        result = me.restart_ap(mac)
        log_command(f"reset_ap_cisco {location_ip} {mac}", "success", get_jwt_identity())
        if result:
            return jsonify({"message": "Access Point reset successfully"}), 200
        else:
            return jsonify({"message": "Failed to reset Access Point"}), 500
    except Exception as e:
        print(f"Error resetting Access Point: {e}")
        return jsonify({"message": "Failed to reset Access Point"}), 500

@app.route('/wifi_config_ubiquity', methods=['GET'])
@jwt_required()
def wifi_config_ubiquity():
    try:
        client = get_unifi_client()
        wlans = client.list_wlanconf()
        wlan_list = []
        for wlan in wlans:
            wlan_info = {
                'WLAN Identifier': wlan.get('_id', 'N/A'),
                'Network Name (SSID)': wlan.get('name', 'N/A'),
                'Radio Policy': ', '.join(wlan.get('wlan_bands', [])),
                'Status': 'Enabled' if wlan.get('enabled', False) else 'Disabled',
                'Security': wlan.get('wpa_mode', 'N/A')
            }
            wlan_list.append(wlan_info)
        log_command("wifi_config_ubiquity", "success", get_jwt_identity())
        return jsonify(wlan_list)
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

def connect_to_ap(hostname, username, password):
    try:
        device = {
            'device_type': 'cisco_wlc',
            'host': hostname,
            'username': username,
            'password': password,
        }
        connection = ConnectHandler(**device)
        print("Connected to the AP")
        return connection
    except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
        print(f"Failed to connect to the AP: {e}")
        return None

@app.route('/show_ap_auto_rf_cisco/<location_ip>/<ap_name>', methods=['GET'])
@jwt_required()
def show_ap_auto_rf_cisco(location_ip, ap_name):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'show ap auto-rf 802.11a {ap_name}'
        output = connection.send_command(command)
        connection.disconnect()
        data = parse_ap_auto_rf_output(output)
        log_command(command, "success", get_jwt_identity())
        return jsonify(data), 200
    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to execute command"}), 500

import re

def parse_ap_auto_rf_output(output):
    data = {}
    lines = output.split('\n')
    current_section = None
    slot_info = None

    main_sections = {
        'Number Of Slots': 'number_of_slots',
        'AP Name': 'ap_name',
        'MAC Address': 'mac_address',
        'Slot ID': 'slot_id',
        'Radio Type': 'radio_type',
        'Sub-band Type': 'sub_band_type',
    }

    for line in lines:
        line = line.strip()
        if not line or line.startswith('--More--') or line.startswith('(Cisco Controller)'):
            continue

        for section, key in main_sections.items():
            if line.startswith(section):
                value = line.split('...')[-1].strip().lstrip('.').strip()
                if key == 'slot_id':
                    current_section = 'slot_info'
                    if 'slot_info' not in data:
                        data['slot_info'] = []
                    slot_info = {key: value}
                    data['slot_info'].append(slot_info)
                else:
                    if current_section == 'slot_info' and slot_info is not None:
                        slot_info[key] = value
                    else:
                        data[key] = value
                break

        if line.startswith('Noise Information'):
            current_section = 'noise_info'
            slot_info[current_section] = {}
        elif line.startswith('Interference Information'):
            current_section = 'interference_info'
            slot_info[current_section] = {}
        elif line.startswith('Load Information'):
            current_section = 'load_info'
            slot_info[current_section] = {}
        elif line.startswith('Coverage Information'):
            current_section = 'coverage_info'
            slot_info[current_section] = {}
        elif line.startswith('Client Signal Strengths'):
            current_section = 'client_signal_strengths'
            slot_info[current_section] = {}
        elif line.startswith('Client Signal To Noise Ratios'):
            current_section = 'client_snr'
            slot_info[current_section] = {}
        elif line.startswith('Nearby APs'):
            current_section = 'nearby_aps'
            slot_info[current_section] = []
        elif line.startswith('Radar Information'):
            current_section = 'radar_info'
            slot_info[current_section] = {}
        elif line.startswith('Channel Assignment Information'):
            current_section = 'channel_assignment_info'
            slot_info[current_section] = {}
        elif line.startswith('RF Parameter Recommendations'):
            current_section = 'rf_parameter_recommendations'
            slot_info[current_section] = {}

        if current_section in ['noise_info', 'interference_info', 'load_info', 'coverage_info', 'client_signal_strengths', 'client_snr', 'radar_info', 'channel_assignment_info', 'rf_parameter_recommendations']:
            if '...' in line:
                key, value = line.split('...', 1)
                slot_info[current_section][key.strip()] = value.strip().lstrip('.').strip()

        elif current_section == 'nearby_aps':
            if line and not line.startswith(('Nearby APs', 'Radar Information', 'Channel Assignment Information', 'RF Parameter Recommendations')):
                slot_info['nearby_aps'].append(line.strip().lstrip('.').strip())

    return data

@app.route('/wifi_config_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def wifi_config_cisco_combined(location_ip):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = 'show wlan summary'
        summary_output = connection.send_command(command)

        summary_data = parse_wifi_config_output(summary_output)
        
        detailed_data = []
        for wlan in summary_data:
            wlan_id = wlan['Wlan_id']
            command = f'show wlan {wlan_id}'
            detail_output = connection.send_command(command)
            detail_config = parse_wlan_config_output(detail_output)
            detailed_data.append({
                **wlan,
                **detail_config
            })

        connection.disconnect()
        log_command(command, "success", get_jwt_identity())
        return jsonify(detailed_data), 200
    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to execute command"}), 500

def parse_wifi_config_output(output):
    pattern = "^[1-9][0-9]*"
    regex = re.compile(pattern)
    wifi = []
    for line in output.splitlines():
        if regex.search(line):
            wlan_id, wlan_profile, _, wlan_ssid, status, interface_name = line.split()[:6]
            wifi.append({
                'Wlan_id': wlan_id,
                'Wlan_profile': wlan_profile,
                'Wlan_ssid': wlan_ssid,
                'Status': status,
                'Interface_name': interface_name
            })
    return wifi

def parse_wlan_config_output(output):
    data = {
        "WLAN Identifier": None,
        "Profile Name": None,
        "Network Name (SSID)": None,
        "Status": None,
        "DHCP Server": None,
        "Radio Policy": None,
        "Radius Servers": {
            "Client Profiling Status": {
                "Radius Profiling": None
            }
        },
        "Maximum Clients Allowed": None,
        "Security": {
            "802.11 Authentication": None,
            "FT Support": None,
            "Static WEP Keys": None,
            "802.1X": None,
            "Wi-Fi Protected Access (WPA/WPA2/WPA3)": None,
            "WPA": None,
            "WPA2": None,
            "WPA3": None
        }
    }

    lines = output.split('\n')
    current_section = None

    main_sections = {
        'WLAN Identifier': 'WLAN Identifier',
        'Profile Name': 'Profile Name',
        'Network Name (SSID)': 'Network Name (SSID)',
        'Status': 'Status',
        'DHCP Server': 'DHCP Server',
        'Radio Policy': 'Radio Policy',
        'Maximum Clients Allowed': 'Maximum Clients Allowed',
        '802.11 Authentication': '802.11 Authentication',
        'FT Support': 'FT Support',
        'Static WEP Keys': 'Static WEP Keys',
        '802.1X': '802.1X',
        'Wi-Fi Protected Access (WPA/WPA2/WPA3)': 'Wi-Fi Protected Access (WPA/WPA2/WPA3)',
        'WPA (SSN IE)': 'WPA',
        'WPA2 (RSN IE)': 'WPA2',
        'WPA3 (RSN IE)': 'WPA3',
    }

    for line in lines:
        line = line.strip()
        if not line or line.startswith('--More--') or line.startswith('(Cisco Controller)'):
            continue

        for section, key in main_sections.items():
            if line.startswith(section):
                value = line.split('...')[-1].strip().lstrip('.').strip()
                if key in data:
                    data[key] = value
                elif key in data['Security']:
                    data['Security'][key] = value
                break

        if line.startswith("Client Profiling Status"):
            current_section = 'Client Profiling Status'
            continue

        if current_section == 'Client Profiling Status':
            if 'Radius Profiling' in line:
                data['Radius Servers']['Client Profiling Status']['Radius Profiling'] = line.split('...')[-1].strip().lstrip('.').strip()

        if line.startswith('Security'):
            current_section = 'Security'
            continue

        if current_section == 'Security':
            if '802.11 Authentication' in line:
                data['Security']['802.11 Authentication'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'FT Support' in line:
                data['Security']['FT Support'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'Static WEP Keys' in line:
                data['Security']['Static WEP Keys'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif '802.1X' in line:
                data['Security']['802.1X'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'Wi-Fi Protected Access (WPA/WPA2/WPA3)' in line:
                data['Security']['Wi-Fi Protected Access (WPA/WPA2/WPA3)'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'WPA (SSN IE)' in line:
                data['Security']['WPA'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'WPA2 (RSN IE)' in line:
                data['Security']['WPA2'] = line.split('...')[-1].strip().lstrip('.').strip()
            elif 'WPA3 (RSN IE)' in line:
                data['Security']['WPA3'] = line.split('...')[-1].strip().lstrip('.').strip()

    return data

@app.route('/create_wlan_cisco', methods=['POST'])
@jwt_required()
def create_wlan_cisco():
    data = request.json
    location_ip = data.get('location_ip')
    wlan_id = data.get('wlan_id')
    wlan_profile = data.get('wlan_profile')
    wlan_ssid = data.get('wlan_ssid')
    security_policy = data.get('security_policy')
    password = data.get('password')
    radio_policy = data.get('radio_policy')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        commands = [
            f'config wlan create {wlan_id} {wlan_profile}',
            f'config wlan ssid {wlan_id} {wlan_ssid}',
            f'config wlan disable {wlan_id}',
            f'config wlan qos {wlan_id} gold', 
            f'config wlan wmm require {wlan_id}',
            f'config wlan uapsd compliant-client enable {wlan_id}'
        ]

        if security_policy == 'WPA2':
            commands.append(f'config wlan security wpa wpa2 enable {wlan_id}')
        elif security_policy == 'WPA3':
            commands.append(f"config wlan security pmf optional {wlan_id}")
            commands.append(f'config wlan security wpa wpa3 enable {wlan_id}')
            commands.append(f"config wlan security wpa wpa3 ciphers aes enable {wlan_id}")
            commands.append(f"config wlan security wpa akm 802.1x disable {wlan_id}")

        if password:
            commands.append(f"config wlan security wpa akm 802.1x disable {wlan_id}")
            commands.append(f"config wlan security wpa akm psk enable {wlan_id}")
            commands.append(f'config wlan security wpa akm psk set-key ascii {password} {wlan_id}')

        if security_policy == 'WPA3':
            commands.append(f'config wlan security wpa akm sae enable {wlan_id}')

        radio_policy_map = {
            '2.4GHz': '802.11bg',
            '5GHz': '802.11a-only',
            '2.4GHz and 5GHz': 'all'
        }
        if radio_policy in radio_policy_map:
            commands.append(f'config wlan radio {wlan_id} {radio_policy_map[radio_policy]}')

        for command in commands:
            output = connection.send_command(command)
            log_command(command, output, get_jwt_identity())
        
        command = f'config wlan enable {wlan_id}'
        connection.send_command(command)

        connection.disconnect()
        return jsonify({"message": "WLAN created successfully"}), 200

    except Exception as e:
        print(f"Error executing command: {e}")
        command = f'config wlan delete {wlan_id}'
        connection.send_command(command)
        connection.disconnect()
        return jsonify({"message": "Failed to execute command"}), 500

@app.route('/delete_wlan_cisco', methods=['POST'])
@jwt_required()
def delete_wlan_cisco():
    data = request.json
    location_ip = data.get('location_ip')
    wlan_id = data.get('wlan_id')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config wlan delete {wlan_id}'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        connection.disconnect()
        return jsonify({"message": "WLAN deleted successfully"}), 200

    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to execute command"}), 500

@app.route('/toggle_wlan_cisco', methods=['POST'])
@jwt_required()
def toggle_wlan_cisco():
    data = request.json
    location_ip = data.get('location_ip')
    wlan_id = data.get('wlan_id')
    status = data.get('status')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config wlan {"enable" if status == "Enabled" else "disable"} {wlan_id}'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        connection.disconnect()
        return jsonify({"message": f"WLAN {status}d successfully"}), 200

    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to execute command"}), 500

@app.route('/toggle_wlan_ubiquity', methods=['POST'])
@jwt_required()
def toggle_wlan_ubiquity():
    data = request.json
    try:
        client = get_unifi_client()
        wlan_id = data['wlan_id']
        status = data['status'] == 'Enabled'
        client.enable_wlan(wlan_id, status)
        log_command(f"toggle_wlan_ubiquity {wlan_id} {'enabled' if status else 'disabled'}", "success", get_jwt_identity())
        return jsonify({"message": f"WLAN {'enabled' if status else 'disabled'} successfully"}), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/update_tftp_config', methods=['POST'])
@jwt_required()
def update_tftp_config():
    data = request.json
    tftp_server_ip = data.get('tftp_server_ip')
    tftp_path = data.get('tftp_path')
    location_ip = data.get('location_ip')
    
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        commands = [
            f'transfer download datatype ap-image',
            f'transfer download ap-images mode tftp',
            f'transfer download ap-images serverIp {tftp_server_ip}',
            f'transfer download ap-images imagePath {tftp_path}'
        ]

        for command in commands:
            output = connection.send_command(command)
            log_command(command, output, get_jwt_identity())
        
        connection.disconnect()
        return jsonify({"message": "TFTP configuration updated successfully"}), 200

    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to update TFTP configuration"}), 500

@app.route('/update_cisco_image', methods=['POST'])
@jwt_required()
def update_cisco_image():
    data = request.json
    location_ip = data.get('location_ip')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = 'transfer download start'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        time.sleep(60)

        commands = [
            'reset system',
            'y',
            'y'
        ]
        for command in commands:
            output = connection.send_command(command)
            log_command(command, output, get_jwt_identity())

        connection.disconnect()
        time.sleep(120)

        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to reconnect to the AP after reboot"}), 500

        command = 'show ap image all'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        connection.disconnect()
        return jsonify({"message": "Cisco image update initiated and verified"}), 200

    except Exception as e:
        print(f"Error executing command: {e}")
        return jsonify({"message": "Failed to initiate Cisco image update"}), 500

def parse_snmpv3_users(output):
    lines = output.split('\n')
    users = []
    for line in lines:
        if '-----' in line or not line.strip():
            continue
        parts = line.split()
        if len(parts) == 4:
            username = parts[0]
            access_mode = parts[1]
            authentication = parts[2]
            encryption = parts[3]
            users.append({
                'username': username,
                'access_mode': access_mode,
                'authentication': authentication,
                'encryption': encryption
            })
    return users

@app.route('/snmpv3_users_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def get_snmpv3_users(location_ip):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = 'show snmpv3user'
        output = connection.send_command(command)
        users = parse_snmpv3_users(output)
        log_command(command, output, get_jwt_identity())
        connection.disconnect()
        return jsonify({"message": "SNMPv3 users retrieved successfully", "data": users}), 200

    except Exception as e:
        print(f"Error retrieving SNMPv3 users: {e}")
        return jsonify({"message": "Failed to retrieve SNMPv3 users"}), 500

@app.route('/snmpv3_user_cisco/delete', methods=['POST'])
@jwt_required()
def delete_snmpv3_user():
    data = request.json
    location_ip = data.get('location_ip')
    username = data.get('username')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config snmp v3user delete {username}'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        connection.disconnect()
        return jsonify({"message": f"SNMPv3 user '{username}' deleted successfully"}), 200

    except Exception as e:
        print(f"Error deleting SNMPv3 user: {e}")
        return jsonify({"message": "Failed to delete SNMPv3 user"}), 500

@app.route('/snmpv3_user_cisco/create', methods=['POST'])
@jwt_required()
def create_snmpv3_user():
    data = request.json
    location_ip = data.get('location_ip')
    username = data.get('username')
    mode = data.get('mode')
    auth_protocol = data.get('auth_protocol')
    priv_protocol = data.get('priv_protocol')
    auth_key = data.get('auth_key')
    priv_key = data.get('priv_key')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config snmp v3user create {username} {mode} {auth_protocol} {priv_protocol} {auth_key} {priv_key}'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        command = 'save config'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())

        commands = [
            'reset system',
            'y',
            'y'
        ]
        for command in commands:
            output = connection.send_command(command)
            log_command(command, output, get_jwt_identity())

        connection.disconnect()
        return jsonify({"message": f"SNMPv3 user '{username}' created and system rebooted successfully"}), 200

    except Exception as e:
        print(f"Error creating SNMPv3 user: {e}")
        return jsonify({"message": "Failed to create SNMPv3 user"}), 500

def parse_master_ap(output):
    for line in output.split('\n'):
        if 'Configured Master AP' in line:
            parts = line.split(':')
            if len(parts) > 1:
                return parts[1].strip()
    return None

@app.route('/master_ap_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def get_master_ap(location_ip):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = 'show ap next-preferred-master'
        output = connection.send_command(command)
        master_ap = parse_master_ap(output)
        connection.disconnect()
        
        if master_ap:
            log_command(command, output, get_jwt_identity())
            return jsonify({"message": "Master AP retrieved successfully", "master_ap": master_ap}), 200
        else:
            return jsonify({"message": "Failed to parse Master AP"}), 500

    except Exception as e:
        print(f"Error retrieving Master AP: {e}")
        return jsonify({"message": "Failed to retrieve Master AP"}), 500

@app.route('/set_master_ap_cisco', methods=['POST'])
@jwt_required()
def set_master_ap():
    data = request.json
    location_ip = data.get('location_ip')
    ap_name = data.get('ap_name')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config ap next-preferred-master {ap_name}'
        output = connection.send_command(command)
        connection.disconnect()
        
        log_command(command, output, get_jwt_identity())
        return jsonify({"message": "Next preferred master AP set successfully", "output": output}), 200

    except Exception as e:
        print(f"Error setting Master AP: {e}")
        return jsonify({"message": "Failed to set Master AP"}), 500

def parse_logs(output):
    return output

@app.route('/set_logging_server_cisco', methods=['POST'])
@jwt_required()
def set_logging_server():
    data = request.json
    location_ip = data.get('location_ip')
    logging_server_ip = data.get('logging_server_ip')

    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = f'config logging syslog host {logging_server_ip}'
        output = connection.send_command(command)
        log_command(command, output, get_jwt_identity())
        connection.disconnect()
        
        return jsonify({"message": "Logging server set successfully", "output": output}), 200

    except Exception as e:
        print(f"Error setting logging server: {e}")
        return jsonify({"message": "Failed to set logging server"}), 500

@app.route('/get_logs_cisco/<location_ip>', methods=['GET'])
@jwt_required()
def get_logs(location_ip):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the AP"}), 500

        command = 'show logging'
        output = connection.send_command(command)
        logs = parse_logs(output)
        log_command(command, output, get_jwt_identity())
        connection.disconnect()
        
        return jsonify({"message": "Logs retrieved successfully", "logs": logs}), 200

    except Exception as e:
        print(f"Error retrieving logs: {e}")
        return jsonify({"message": "Failed to retrieve logs"}), 500

@app.route('/save_config_cisco/<location_ip>', methods=['POST'])
@jwt_required()
def save_config_cisco(location_ip):
    try:
        connection = connect_to_ap(location_ip, 'rmocanu001', 'pass')
        if not connection:
            return jsonify({"message": "Failed to connect to the Cisco Mobility Express controller"}), 500

        command = 'save config'
        output = connection.send_command_timing(command)
        
        if 'Are you sure you want to save? (y/n)' in output:
            output += connection.send_command_timing('y')

        log_command(command, output, get_jwt_identity())
        connection.disconnect()
        return jsonify({"message": "Configuration saved successfully"}), 200

    except Exception as e:
        print(f"Error saving configuration: {e}")
        return jsonify({"message": "Failed to save configuration"}), 500
    
@app.route('/save_config_ubiquity', methods=['POST'])
@jwt_required()
def save_config_ubiquity():
    try:
        client = get_unifi_client()
        log_command('save_config_ubiquity', 'Attempt to save configuration', get_jwt_identity())
        client.logout()
        log_command('save_config_ubiquity', 'Configuration saved and logged out successfully', get_jwt_identity())
        
        return jsonify({"message": "Configuration saved and logged out successfully"}), 200

    except Exception as e:
        print(f"Error saving configuration: {e}")
        log_command('save_config_ubiquity', f"Failed to save configuration: {str(e)}", get_jwt_identity())
        return jsonify({"message": "Failed to save configuration"}), 500

if __name__ == '__main__':
    app.run(debug=True)
