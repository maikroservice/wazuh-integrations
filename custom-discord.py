#/usr/bin/env python3

import sys
import requests
requests.auth import HTTPBasicAuth

# read configuration
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# extract alert fields
alert_level = alert_json["rule"]["level"]

if(alert_level >= 5 and alert_level <= 11):
	# yellow
    color = "15919874"
elif(alert_level >= 12):
    # red
    color = "15870466"

# agent details
if "agentless" in alert_json:
	  agent_ = "agentless"
else:
    agent_ = alert_json["agent"]["name"]

# combine message details
payload = json.dumps({
    "content": "",
    "embeds": [
        {
		    "title": f"Wazuh Alert - Rule {alert_json['rule']['id']}",
				"color": color,
				"description": alert_json["rule"]["description"],
				"fields": [{
						"name": "Agent",
						"value": _agent,
						"inline": True
						}]
        }
    ]
})

# send message to discord
r = requests.post(hook_url, data=payload, headers={"content-type": "application/json"}
sys.exit(0)