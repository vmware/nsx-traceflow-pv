# VMware has ended active development of this project, this repository will no longer be updated.
###API Document for Traceflow Tool

This is the API Document for the NSX End-to-end Traceflow Visualization Tool.

**Current Server Address/Port: 10.34.226.46:5000** 

1. Get VM List
url: **GET http://server-addr:port/api/vms**
Response
<pre><code>{
   "vms": [{
	      "ip": "30.30.30.10",
	      "mac": "00:50:56:9d:fd:82",
	      "name": "HV2-VM10",
	      "network": "vxw-dvs-226-virtualwire-10-sid-5002-App",
	      "uuid": "501d9a6f-b07b-1ffe-e43b-ad3851f5a3a8"
		}, {
	      "ip": "30.30.30.2",
	      "mac": "00:50:56:9d:df:2b",
	      "name": "HV2-VM2",
	      "network": "vxw-dvs-226-virtualwire-10-sid-5002-App",
	      "uuid": "501da9eb-62d4-33ac-4441-f598cbe138cd"
     }]
}
</code></pre>

2. Send Traceflow Request
url: **POST http://server-addr:port/api/traceflow**
Request Body:
<pre><code>{
		"vm1" : {
			"ip": "30.30.30.10",
			"mac": "00:50:56:9d:fd:82",
			"name": "HV2-VM10",
			"network": "vxw-dvs-226-virtualwire-10-sid-5002-App",
			"uuid": "501d9a6f-b07b-1ffe-e43b-ad3851f5a3a8"
		},
		"vm2" : {
			"ip": "30.30.30.2”,
			"mac": "00:50:56:9d:df:2b",
			"name": "HV2-VM2",
			"network": "vxw-dvs-226-virtualwire-10-sid-5002-App",
			"uuid": "501da9eb-62d4-33ac-4441-f598cbe138cd
		}
}
</code></pre>
Response Body: Result URL

