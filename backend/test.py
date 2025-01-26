from unificontrol import UnifiClient
import urllib3

# Disable SSL warnings (for testing purposes)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Correct host and port for UniFi controller
client = UnifiClient(host="localhost", port=8443, username='rmocanu001', password="pass", site="default")

try:
    client.login()
    print("Logged in to the controller")
    devices = client.list_devices_basic()
    print(devices)
except Exception as e:
    print(f"Error: {str(e)}")
