#!/usr/bin/env python

#nsx-traceflow-pv Backend
#Authors: Nitish Limaye, Tripti Attavar, Qichao Chu

import atexit
import requests
import threading
import time
import json
import subprocess
import uuid
import MySQLdb
import pickle
from warnings import filterwarnings
from flask import Flask, jsonify, request, Response
from pyVim import connect
from lxml import etree
from flask.ext.cors import CORS
from jsonrpclib import Server
from requests.packages.urllib3.exceptions import InsecureRequestWarning

app = Flask(__name__)
CORS(app)
app.debug = True
maxdepth = 10
datacenter_list = []
vm_vtep_ip_map = {}
vm_object_list = []
traceflow_records = {}
ip_list=["10.114.211.7", "10.114.211.5", "10.114.211.18", "10.114.211.249"]
nsx_mgmt_info = {}
vm_network_filter = ""
vcenter_mgmt_info = {}
db_mgmt_info = {}
batch_data = {}
vtep_list = []

#---------------------------------Switch---------------------------------

def get_hostname(ip_list):
    ip_to_hostname = {}
    for ip in ip_list:
        switch_cli = Server( "http://admin:ca$hc0w@"+ip+"/command-api" )
        response_hostname = switch_cli.runCmds( 1, ["show hostname"])
        ip_to_hostname[ip] = response_hostname[0]["hostname"]
    return ip_to_hostname

def get_ports(ip_to_hostname):
    ip_port_dict = {}
    all_ports = []
    for ip in ip_to_hostname.keys():
        switch_cli = Server( "http://admin:ca$hc0w@"+ip+"/command-api" )
        response_lldp = switch_cli.runCmds( 1, ["enable","show lldp neighbors"])
        port_list = []
        for i in response_lldp[1]["lldpNeighbors"]:
            if i["neighborDevice"] in ip_to_hostname.values():
                port_list.append(i["port"])
        if len(port_list) > 1:
            portchannel_interface = switch_cli.runCmds( 1, ["show interfaces "+port_list[0]+" status"])
            po_n = portchannel_interface[0]["interfaceStatuses"][port_list[0]]["vlanInformation"]["vlanExplanation"][3:]
            port_list.append(po_n)
        ip_port_dict[ip] = port_list
    
    ip_port_dict["10.114.211.7"].append("Ethernet10")
    ip_port_dict["10.114.211.5"].append("Ethernet9")
    
    return ip_port_dict
    
def find_topology(ip_list):
    ip_to_hostname = get_hostname(ip_list)
    adjacency_list = {}
    for ip in ip_to_hostname.keys():
        switch_cli = Server("http://admin:ca$hc0w@"+ip+"/command-api")
        response_lldp = switch_cli.runCmds(1,["enable","show lldp neighbors"])
        
        adjacency_list[ip] = {}
        
        #print ip
        for index in range(len(response_lldp[1]["lldpNeighbors"])):
            if (response_lldp[1]["lldpNeighbors"][index]['neighborDevice'] in ip_to_hostname.values()):
                if (response_lldp[1]["lldpNeighbors"][index]['neighborDevice'] in adjacency_list[ip].keys()):
                    portchannel_interface = switch_cli.runCmds( 1, ["show interfaces "+response_lldp[1]["lldpNeighbors"][index]['port']+" status"])
                    po_n = portchannel_interface[0]["interfaceStatuses"][response_lldp[1]["lldpNeighbors"][index]['port']]["vlanInformation"]["vlanExplanation"][3:]
                    adjacency_list[ip][response_lldp[1]["lldpNeighbors"][index]['neighborDevice']] = po_n
                else :
                    adjacency_list[ip][response_lldp[1]["lldpNeighbors"][index]['neighborDevice']] = response_lldp[1]["lldpNeighbors"][index]['port']
            elif (response_lldp[1]["lldpNeighbors"][index]['neighborDevice'] == "localhost"):
                adjacency_list[ip][response_lldp[1]["lldpNeighbors"][index]['neighborDevice']] = response_lldp[1]["lldpNeighbors"][index]['port']
    return adjacency_list

def configure_acl(ip_list,vtep_list,udp_source_port):
    adjacency_list = find_topology(ip_list)
    for ip in adjacency_list.keys():
        switch_cli = Server( "http://admin:ca$hc0w@"+ip+"/command-api" )
        configure_acl_response = switch_cli.runCmds( 1, ["enable","configure terminal","ip access-list trace",
        "statistics per-entry",
        "10 permit udp host "+vtep_list[0]+" eq "+udp_source_port+" host "+vtep_list[1],
        "20 permit udp host "+vtep_list[1]+" eq "+udp_source_port+" host "+vtep_list[0],
        "30 permit ip any any"])
        for interface in adjacency_list[ip].values():
            configure_acl_interface_response = switch_cli.runCmds( 1, ["enable","configure terminal",
            "interface "+interface,
            "ip access-group trace in",
            "end"])
    switch_acl_counters_old = get_statistics(ip_list)
    return switch_acl_counters_old
    
def get_statistics(ip_list):
    switch_acl_counters = {}
    ip_to_hostname = get_hostname(ip_list)
    for ip in ip_list:
        switch_cli = Server( "http://admin:ca$hc0w@"+ip+"/command-api" )
        response = switch_cli.runCmds( 1, ["enable","show ip access-lists trace"])
        switch_acl_counters[ip] = []
        for items in response[1]["aclList"][0]["sequence"]:
            if "packetCount" in items["counterData"]:
                switch_acl_counters[ip].append(int(items["counterData"]["packetCount"]))
            else:
                switch_acl_counters[ip].append(0)
    return switch_acl_counters
       
def remove_acl(ip_list):
    adjacency_list = find_topology(ip_list)
    for ip in adjacency_list.keys():
        switch_cli = Server( "http://admin:ca$hc0w@"+ip+"/command-api" )
        configure_acl_response = switch_cli.runCmds( 1, ["enable","configure terminal","no ip access-list trace",])
        for interface in adjacency_list[ip].values():
            configure_acl_interface_response = switch_cli.runCmds( 1, ["enable","configure terminal",
            "interface "+interface,
            "no ip access-group trace in",
            "end"])

def get_switch_list(ip_list,switch_acl_counters_old):
    adjacency_list = find_topology(ip_list)
    ip_to_hostname = get_hostname(ip_list)
    switch_acl_counters_new = {}
    
    #Getting the new counter values
    switch_acl_counters_new = {}
    switch_acl_counters_new = get_statistics(ip_list)   
    
    #Comparing old and new counters
    no_of_acl_rules = len(switch_acl_counters_new[ip_list[0]])
    #print no_of_acl_rules
    rule_hitting_in_switch = {}
    for i in range(len(switch_acl_counters_old[ip_list[0]])-1):
        for items in switch_acl_counters_new.keys():
            if switch_acl_counters_new[items][i] > (switch_acl_counters_old[items][i]+1):
                if i in rule_hitting_in_switch.keys():
                    rule_hitting_in_switch[i].append(items)
                else:
                    rule_hitting_in_switch[i] = []
                    rule_hitting_in_switch[i].append(items)
    #return rule_hitting_in_switch
    s_list = []
    if (0 in rule_hitting_in_switch.keys()):
        s_list = ["prmh-nsx-tme-7150s-1","prmh-nsx-tme-7050qx-2","prmh-nsx-tme-7150s-2"]
    elif (1 in rule_hitting_in_switch.keys()):
        s_list = ["prmh-nsx-tme-7150s-2","prmh-nsx-tme-7050qx-2","prmh-nsx-tme-7150s-1"]
    #print s_list
    hostname_to_ip = {}
    for ip in ip_list:
        hostname_to_ip[ip_to_hostname[ip]] = ip
    ordered_switch_list = []
    for i in range(len(s_list)):
        temp={}
        temp["ip"] = hostname_to_ip[s_list[i]]
        temp["hostname"] = s_list[i]
        ordered_switch_list.append(temp)
    return ordered_switch_list

def find_ordered_switch_list(ip_list,vtep_list,rule_hitting_in_switch):
    if len(rule_hitting_in_switch) ==0 :
        return []
    adjacency_list = find_topology(ip_list)
    ip_to_hostname = get_hostname(ip_list)
    hostname_to_ip = {}
    for ip in ip_list:
        hostname_to_ip[ip_to_hostname[ip]] = ip
    #print hostname_to_ip
    ordered_switch_list = []    
    source = {}
    rule = 0
    if 0 in rule_hitting_in_switch.keys():
        rule = 0
        source[rule] = vtep_list[0]
    elif 1 in rule_hitting_in_switch.keys():
        rule = 1
        source[rule] = vtep_list[1]
    
    source_switch = "localhost" 
    length = len(rule_hitting_in_switch[rule])
    for i in range(length):
        switch = find_source_switch(rule_hitting_in_switch[rule],source_switch,adjacency_list,source[rule])
        ordered_switch_list.append(ip_to_hostname[switch])
        rule_hitting_in_switch[rule].remove(switch)
        source_switch = ip_to_hostname[switch]
    return ordered_switch_list
               
def find_neighbor(ip,interface,adjacency_list):
    flag = "false"
    for nei_iterator in adjacency_list[ip].keys():
        #print adjacency_list[ip][nei_iterator]," : ",interface
        if (adjacency_list[ip][nei_iterator] == interface):
            return nei_iterator
        elif ((adjacency_list[ip][nei_iterator][0:2] == 'Po') and (interface[0:2]) == 'Po'):
            if(adjacency_list[ip][nei_iterator][-2:] == interface[-2:]):
                return nei_iterator
    return ""
    
def find_source_switch(unsorted_switch_list,source_switch,adjacency_list,source_ip):
    for i in range(len(unsorted_switch_list)):
        for switch in unsorted_switch_list:
            #print switch 
            switch_cli = Server( "http://admin:ca$hc0w@"+switch+"/command-api" )
            response_arp = switch_cli.runCmds( 1, ["enable","show ip arp"])
            arp_list = response_arp[1]["ipV4Neighbors"]
            interface_name = ""
            for num in range(len(arp_list)):
                if arp_list[num]["address"] == source_ip:
                    interface_name = arp_list[num]["interface"].split(' ')[1]
                    break
            nei = find_neighbor(switch,interface_name,adjacency_list)
            if nei == source_switch :
                return switch

#---------------------------------Thread---------------------------------

class check_tf_complete_thread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        while(not traceflow_records[self.name]['completed']):
            time.sleep(0.5)
            query_and_update_result(self.name)
        print("Traceflow " + self.name + " has completed.")

class batch_job_thread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
    def run(self):
        run_the_for_loop(self.name)

def run_the_for_loop(batchid):
    global batch_data
    content = batch_data[batchid]
    for i in range(0, len(content['vms'])):
        for j in range(i + 1, len(content['vms'])):
            sub_content = {
                            'vm1': content['vms'][i],
                            'vm2': content['vms'][j] 
                        }
            record = insert_recourd_with_batch_id(sub_content, batchid)
            traceflow_id = do_traceflow(sub_content, record)
            thread = check_tf_complete_thread(len(traceflow_records), traceflow_id, 0)
            thread.start()
            time.sleep(30)

#---------------------------------Backend---------------------------------

def initialization():
    global datacenter_list
    global vm_vtep_ip_map
    global nsx_mgmt_info
    global vm_network_filter
    global vcenter_mgmt_info
    db_and_global_var_init()
    service_instance = connect.SmartConnect(host=vcenter_mgmt_info['host'],
                                            user=vcenter_mgmt_info['username'],
                                            pwd =vcenter_mgmt_info['password'],
                                            port=int(vcenter_mgmt_info['port']))
    atexit.register(connect.Disconnect, service_instance)
    content = service_instance.RetrieveContent()
    datacenter_list = content.rootFolder.childEntity
    get_raw_vms()

    for vm in vm_object_list:
        hostForThisVm = vm.summary.runtime.host
        vNicConfigInfoArray = hostForThisVm.configManager.virtualNicManager.info.netConfig
        vNicConfigInfo = vNicConfigInfoArray[0]
        nicList = vNicConfigInfo.candidateVnic
        for nicConfig in nicList:
            netStackInstanceKey = nicConfig.spec.netStackInstanceKey
            if netStackInstanceKey == "vxlan":
                if (vm.summary.config.instanceUuid in vm_vtep_ip_map):
                    vm_vtep_ip_map[vm.summary.config.instanceUuid].append(nicConfig.spec.ip.ipAddress)
                else:
                    vtep_list = []
                    vtep_list.append(nicConfig.spec.ip.ipAddress)
                    vm_vtep_ip_map[vm.summary.config.instanceUuid] = vtep_list

def update_raw_vm_list(vm):
    global vm_object_list
    if hasattr(vm, 'childEntity'):
        vmList = vm.childEntity
        for c in vmList:
            update_raw_vm_list(c)
        return
    guest_info = vm.guest
    if guest_info is not None:
            if guest_info.net is not None:
                if len(guest_info.net) > 0:
                    for nic in guest_info.net:
                        if (nic.network is not None and nic.network.startswith(vm_network_filter)):
                            vm_object_list.append(vm)

def get_raw_vms():
    global datacenter_list
    for datacenter in datacenter_list:
        if hasattr(datacenter, 'vmFolder'):
            thisDatacenterVmList = datacenter.vmFolder.childEntity
            for vm in thisDatacenterVmList:
                update_raw_vm_list(vm)

def do_traceflow(content, record):
    global traceflow_records
    global ip_list
    global vtep_list
    vm1_ip = content['vm1']['ip']
    vm1_uuid = content['vm1']['uuid']
    vm1_mac = content['vm1']['mac']
    vm1_vtep_ip = vm_vtep_ip_map[content['vm1']['uuid']][0]
    vm2_ip = content['vm2']['ip']
    vm2_mac = content['vm2']['mac']
    vm2_vtep_ip = vm_vtep_ip_map[content['vm2']['uuid']][0]
    vtep_list = [vm1_vtep_ip, vm2_vtep_ip]
    udp_port = calc_port(content['vm1']['ip'], content['vm2']['ip'], 'icmp')
    returned_dictionary = configure_acl(ip_list, vtep_list, udp_port)
    traceflow_id = nsx_do_traceflow(vm1_uuid, vm1_ip, vm2_ip, vm1_mac, vm2_mac)
    traceflow_records[traceflow_id] = record
    traceflow_records[traceflow_id]['returned_dictionary'] = returned_dictionary
    return traceflow_id

def result_process(true_result):
    result_tree = etree.fromstring(true_result.content)
    node_list = []
    phy_node_xml_list = result_tree.find('traceflowObservationsDataPage').findall('traceflowObservationReceived')
    for node in phy_node_xml_list:
        info_dict = {}
        info_dict['transportNodeId'] = node.find('transportNodeId').text
        info_dict['hostName'] = node.find('hostName').text
        info_dict['hostId'] = node.find('hostId').text
        info_dict['component'] = node.find('component').text
        info_dict['compDisplayName'] = node.find('compDisplayName').text
        info_dict['hopCount'] = int(node.find('hopCount').text)
        node_list.append(info_dict)

    logical_node_xml_list = result_tree.find('traceflowObservationsDataPage').findall('traceflowObservationLogicalReceived')
    for node in logical_node_xml_list:
        info_dict = {}
        info_dict['transportNodeId'] = node.find('transportNodeId').text
        info_dict['hostName'] = node.find('hostName').text
        info_dict['hostId'] = node.find('hostId').text
        info_dict['component'] = node.find('component').text
        info_dict['compDisplayName'] = node.find('compDisplayName').text
        info_dict['hopCount'] = int(node.find('hopCount').text)
        node_list.append(info_dict)

    logical_forward_xml_list = result_tree.find('traceflowObservationsDataPage').findall('traceflowObservationForwarded')
    for node in logical_forward_xml_list:
        info_dict = {}
        info_dict['transportNodeId'] = node.find('transportNodeId').text
        info_dict['hostName'] = node.find('hostName').text
        info_dict['hostId'] = node.find('hostId').text
        info_dict['component'] = node.find('component').text
        info_dict['compDisplayName'] = node.find('compDisplayName').text
        info_dict['hopCount'] = int(node.find('hopCount').text)
        node_list.append(info_dict)

    logical_forward_xml_list = result_tree.find('traceflowObservationsDataPage').findall('traceflowObservationLogicalForwarded')
    for node in logical_forward_xml_list:
        info_dict = {}
        info_dict['transportNodeId'] = node.find('transportNodeId').text
        info_dict['hostName'] = node.find('hostName').text
        info_dict['hostId'] = node.find('hostId').text
        info_dict['component'] = node.find('component').text
        info_dict['compDisplayName'] = node.find('compDisplayName').text
        info_dict['hopCount'] = int(node.find('hopCount').text)
        node_list.append(info_dict)

    delivered_xml_list = result_tree.find('traceflowObservationsDataPage').findall('traceflowObservationDelivered')
    for node in delivered_xml_list:
        info_dict = {}
        info_dict['transportNodeId'] = node.find('transportNodeId').text
        info_dict['hostName'] = node.find('hostName').text
        info_dict['hostId'] = node.find('hostId').text
        info_dict['component'] = node.find('component').text
        info_dict['compDisplayName'] = node.find('compDisplayName').text
        info_dict['hopCount'] = int(node.find('hopCount').text)
        node_list.append(info_dict)

    node_list = sorted(node_list, key=lambda node: node['hopCount'])
    return node_list

def nsx_do_traceflow(vm1_uuid, vm1_ip, vm2_ip, vm1_mac, vm2_mac):
    url = nsx_mgmt_info['base_url']
    root = etree.Element('traceflowRequest')
    headers = {'Content-Type': 'text/xml'}

    vnicId = etree.Element('vnicId')
    vnicId.text = vm1_uuid + '.000'
    root.append(vnicId)

    timeout = etree.Element('timeout')
    timeout.text = '10000'
    root.append(timeout)

    routed = etree.Element('routed')
    routed.text = 'true'
    root.append(routed)

    packet = etree.Element('packet')
    packet.attrib['class'] = 'fieldsPacketData'

    resourceType = etree.Element('resourceType')
    resourceType.text = 'FieldsPacketData'
    packet.append(resourceType)

    ethHeader = etree.Element('ethHeader')
    srcMac = etree.Element('srcMac')
    srcMac.text = vm1_mac
    ethHeader.append(srcMac)
    dstMac = etree.Element('dstMac')
    dstMac.text = vm2_mac
    ethHeader.append(dstMac)
    ethType = etree.Element('ethType')
    ethType.text = '2048'
    ethHeader.append(ethType)
    packet.append(ethHeader)

    ipHeader = etree.Element('ipHeader')
    ttl = etree.Element('ttl')
    ttl.text = '64'
    ipHeader.append(ttl)
    srcIp = etree.Element('srcIp')
    srcIp.text = vm1_ip
    ipHeader.append(srcIp)
    dstIp = etree.Element('dstIp')
    dstIp.text = vm2_ip
    ipHeader.append(dstIp)
    packet.append(ipHeader)

    root.append(packet)
    request_data = etree.tostring(root, pretty_print=True, encoding='UTF-8')

    response = requests.post(url, data=request_data, auth=('root', 'vmware'), verify=False, headers=headers)
    response = requests.post(url, data=request_data, auth=('root', 'vmware'), verify=False, headers=headers)
    response = requests.post(url, data=request_data, auth=('root', 'vmware'), verify=False, headers=headers)
    traceflow_id = response.text
    return traceflow_id

def query_and_update_result(traceflow_id):
    global traceflow_records
    global ip_list
    url = nsx_mgmt_info['base_url'] + '/' + traceflow_id + '/observations'
    check_result = requests.get(url, auth=(nsx_mgmt_info['username'], nsx_mgmt_info['password']), verify=False)
    tree = etree.fromstring(check_result.content)
    if (tree.tag == 'error'):
        return
    else: 
        traceflow_records[traceflow_id]['completed'] = True
        true_result = requests.get(url, auth=(nsx_mgmt_info['username'], nsx_mgmt_info['password']), verify=False)
        processed_result = result_process(true_result)
        traceflow_records[traceflow_id]['result'] = processed_result
        if (len(processed_result) > 1 and processed_result[len(processed_result) - 1]['compDisplayName'] == "vNIC"):
            traceflow_records[traceflow_id]['success'] = True
        switch_result = get_switch_list(ip_list, traceflow_records[traceflow_id]['returned_dictionary'])
        traceflow_records[traceflow_id]['physical'] = switch_result
        remove_acl(ip_list)
        insert_record_query(traceflow_id)

def json_load_byteified(file_handle):
    return _byteify(
        json.load(file_handle, object_hook=_byteify),
        ignore_dicts=True
    )

def json_loads_byteified(json_text):
    return _byteify(
        json.loads(json_text, object_hook=_byteify),
        ignore_dicts=True
    )

def _byteify(data, ignore_dicts = False):
    if isinstance(data, unicode):
        return data.encode('utf-8')
    if isinstance(data, list):
        return [ _byteify(item, ignore_dicts=True) for item in data ]
    if isinstance(data, dict) and not ignore_dicts:
        return {
            _byteify(key, ignore_dicts=True): _byteify(value, ignore_dicts=True)
            for key, value in data.iteritems()
        }
    return data

def get_component_from_list(list, type, key):
    result = []
    for component in list:
        if component[key] == type:
            result.append(component)
    return result

def mark_invisible(component):
    component['visible'] = False

def is_invisible(component):
    return component['visible']

def calc_port(srcip, dstip, proto):
    shell_cmd = '/etc/nsx-traceflow-tool/traceflow --ipv4 ' + srcip + ' ' + dstip + ' ' + proto
    port_num = subprocess.Popen(shell_cmd, shell=True, stdout=subprocess.PIPE).stdout.read()
    port_num_arr = (port_num.rstrip()).split()
    return port_num_arr[len(port_num_arr) - 1]

def insert_recourd_with_batch_id(content, batchid):
    record = {}
    record['info'] = content
    record['completed'] = False
    record['success'] = True
    record['result'] = []
    record['batchid'] = batchid
    record['returned_dictionary'] = {}
    record['port'] = calc_port(content['vm1']['ip'], content['vm2']['ip'], 'icmp')
    return record 

def insert_recourd(content):
    return insert_recourd_with_batch_id(content, None)

def insert_record_query(traceflow_id):
    global traceflow_records
    global db_mgmt_info
    db = MySQLdb.connect(db_mgmt_info['ip'], db_mgmt_info['username'], db_mgmt_info['password'], db_mgmt_info['db'])
    conn = db.cursor()
    content = traceflow_records[traceflow_id]['info']
    vm1_ip = content['vm1']['ip']
    vm1_uuid = content['vm1']['uuid']
    vm1_mac = content['vm1']['mac']
    vm2_ip = content['vm2']['ip']
    vm2_uuid = content['vm2']['uuid']
    vm2_mac = content['vm2']['mac']
    record = traceflow_records[traceflow_id]
    pdata = pickle.dumps(record)
    tr_success = traceflow_records[traceflow_id]['success']
    batchid = traceflow_records[traceflow_id]['batchid']
    base_sql = 'INSERT INTO TRACEDATA (ID, SRCIP, DSTIP, SRCMAC, DSTMAC, SRCUUID, DSTUUID, SUCCESS, BATCHID, RESULT) VALUES ("%s", "%s", "%s", "%s", "%s", "%s", "%s", %s, "%s", "%s")'
    conn.execute(base_sql % (traceflow_id, vm1_ip, vm2_ip, vm1_mac, vm2_mac, vm1_uuid, vm2_uuid, tr_success, batchid ,pdata))
    db.commit()
    db.close()

def db_and_global_var_init():
    global nsx_mgmt_info
    global vm_network_filter
    global vcenter_mgmt_info
    global db_mgmt_info
    with open('/etc/nsx-traceflow-tool/config.json') as config_file:    
        config_data = json.load(config_file)
    vm_network_filter = config_data['vm_network_filter']
    db_mgmt_info = config_data['db_info']
    db = MySQLdb.connect(db_mgmt_info['ip'], db_mgmt_info['username'], db_mgmt_info['password'], db_mgmt_info['db'])
    conn = db.cursor()
    conn.execute('''CREATE TABLE IF NOT EXISTS TRACEDATA (   
                    id      varchar(50) PRIMARY KEY NOT NULL,
                    srcip   char(20)                NOT NULL,
                    dstip   char(20)                NOT NULL,
                    srcmac  char(20)                NOT NULL,
                    dstmac  char(20)                NOT NULL,
                    srcuuid varchar(50)             NOT NULL,
                    dstuuid varchar(50)             NOT NULL,
                    success boolean                 NOT NULL,
                    batchid varchar(50)                     ,
                    result  varchar(50000)          NOT NULL)''')

    conn.execute('''CREATE TABLE IF NOT EXISTS CONFIG (   
                    ip          varchar(20) PRIMARY KEY NOT NULL,
                    username    varchar(20)             NOT NULL,
                    password    varchar(20)             NOT NULL,
                    type        varchar(20)             NOT NULL,
                    port        INT     )''')

    conn.execute('SELECT * FROM CONFIG')
    config_data = conn.fetchall()
    for row in config_data:
        if row[3] == "nsx":
            nsx_mgmt_tr_url = 'https://' + row[0] + '/api/2.0/vdn/traceflow'
            nsx_mgmt_info = {
                'base_url': nsx_mgmt_tr_url,
                'username': row[1],
                'password': row[2]
            }
        elif row[3] == "vcenter":
            vcenter_mgmt_info = {
                'host': row[0],
                'username': row[1],
                'password': row[2],
                'port': row[4]
            }

    db.commit()    
    db.close()

@app.route('/api/vms', methods=['GET'])
def get_vm_list():
    vms = []
    for vm in vm_object_list:
        if hasattr(vm, 'summary') and hasattr(vm, 'guest'):
            if hasattr(vm.summary, 'config'):
                    summary = vm.summary
                    guest_info = vm.guest
                    config = summary.config
                    vms.append({
                            'ip'   : guest_info.net[0].ipAddress[0],
                            'mac'  : guest_info.net[0].macAddress,
                            'network': guest_info.net[0].network,
                            'name' : config.name,
                            'uuid' : config.instanceUuid
                        })
    return jsonify({'vms' : vms})

@app.route('/api/update', methods=['GET'])
def getUpdateStatus():
    initialization()
    return "Update Success"

@app.route('/api/traceflow/<traceflow_id>', methods=['GET'])
def get_result(traceflow_id):
    data = traceflow_records[traceflow_id]
    return jsonify(data)

@app.route('/api/traceflow/batch', methods=['POST'])
def do_trace_with_multiple_machine():
    global batch_data
    batchid = str(uuid.uuid4())
    content = request.get_json()
    batch_data[batchid] = content
    batch_thread = batch_job_thread(len(batch_data), batchid, 0)
    batch_thread.start()
    return jsonify({'batchid' : batchid})

@app.route('/api/traceflow', methods=['POST'])
def postTraceflowInfo():
    global traceflow_records
    content = request.get_json()
    record = insert_recourd(content)
    traceflow_id = do_traceflow(content, record)
    thread = check_tf_complete_thread(len(traceflow_records), traceflow_id, 0)
    thread.start()
    return jsonify({'id' : traceflow_id})

@app.route('/api/traceflow/html', methods=['POST'])
def post_do_traceflow_html():
    global traceflow_records
    render_url = 'http://10.34.226.46:8088/bootcamp-fe/d3.html'
    content = request.get_json()
    record = insert_recourd(content)
    traceflow_id = do_traceflow(content, record)
    while(not traceflow_records[traceflow_id]['completed']):
            time.sleep(0.5)
            query_and_update_result(traceflow_id)
    raw_result_arr = traceflow_records[traceflow_id]['result']
    
    raw2_result_arr = []
    host_1_key = raw_result_arr[0]['hostId']
    dst_key = raw_result_arr[len(raw_result_arr) - 1]['hostId']

    if (host_1_key == dst_key):
        for node in raw_result_arr:
            if (not node['component'] == 'LR'):
                raw2_result_arr.append(node)
    else:
        for node in raw_result_arr:
            raw2_result_arr.append(node)

    result_arr = []
    for node in raw2_result_arr:
        if (not node['component'] == 'BRIDGE'):
            result_arr.append(node)

    with open('/var/www/bootcamp-fe/logicalplane.json') as logicjson_file:    
        logic_data = json_load_byteified(logicjson_file)

    vds = logic_data[0]
    vdr = vds['children'][0]
    dfw2 = vds['children'][1]
    vm2  = dfw2['children'][0]
    ovs = vdr['children'][0]
    dfw1 = ovs['children'][0]
    vm1 = dfw1['children'][0]

    vds['visible'] = True
    vdr['visible'] = True
    dfw2['visible'] = True
    vm2['visible'] = True
    ovs['visible'] = True
    dfw1['visible'] = True
    vm1['visible'] = True

    vds_i = result_arr[0]
    vdr_i = result_arr[0]
    vm1_i = result_arr[0]
    vm2_i = result_arr[0]
    ovs_i = result_arr[0]
    dfw1_i = result_arr[0]
    dfw2_i = result_arr[0]

    host_1 = []
    host_2 = []

    host_1_key = result_arr[0]['hostId']
    for node in result_arr:
        if (node['hostId'] == host_1_key):
            host_1.append(node)
        else:
            host_2.append(node)

    switch_list = get_component_from_list(host_1, 'LS', 'component')

    if (len(switch_list) > 1):
        ovs_i = switch_list[0]
        if (dst_key == host_1_key):
            mark_invisible(ovs)
        vds_i = switch_list[1]
    elif(len(switch_list) > 0):
        vds_i = switch_list[0]
        mark_invisible(ovs)
    else:
        mark_invisible(ovs)
        mark_invisible(dvs)

    router_list = get_component_from_list(host_1, 'LR', 'component')
    if (len(router_list) > 0):
        vdr_i = router_list[0]
        vdr_i['compDisplayName'] = 'Router'
    else:
        mark_invisible(vdr)

    fw2_list = get_component_from_list(host_2, 'FW', 'component')
    if (len(fw2_list) > 0):
        dfw2_i = fw2_list[0]
    else:
        mark_invisible(dfw2)
    fw1_list = get_component_from_list(host_1, 'FW', 'component')
    if (len(fw1_list) > 2):
        dfw1_i = fw1_list[0]
        dfw2_i = fw1_list[2]
        dfw2['visible'] = True
    elif (len(fw1_list) > 0):
        dfw1_i = fw1_list[0]
    else:
        mark_invisible(dfw1)

    print(dfw2['visible'])

    vm2_list = get_component_from_list(host_2, 'vNIC', 'compDisplayName')
    if (len(vm2_list) > 0):
        vm2_i = vm2_list[0]
    else:
        mark_invisible(vm2)
    vm1_list = get_component_from_list(host_1, 'vNIC', 'compDisplayName')
    if (len(vm1_list) > 1):
        vm1_i = vm1_list[0]
        vm2_i = vm1_list[1]
        vm2['visible'] = True
    elif (len(vm1_list) == 1):
        vm1_i = vm1_list[0]    
    else:
        mark_invisible(vm1)

    if(vds['visible'] ): vds['name']  = vds_i['compDisplayName']
    if(vdr['visible'] ): vdr['name']  = vdr_i['compDisplayName']
    if(ovs['visible'] ): ovs['name']  = ovs_i['compDisplayName']
    if(vm1['visible'] ): vm1['name']  = vm1_i['compDisplayName']
    if(vm2['visible'] ): vm2['name']  = vm2_i['compDisplayName']
    if(dfw2['visible']): dfw2['name'] = dfw2_i['compDisplayName']
    if(dfw1['visible']): dfw1['name'] = dfw1_i['compDisplayName']

    if(vds['visible'] ): vds['info']  = str(vds_i['hopCount'] ) + ' ' + vds_i['hostId']  + ' ' + vds_i['component']
    if(vdr['visible'] ): vdr['info']  = str(vdr_i['hopCount'] ) + ' ' + vdr_i['hostId']  + ' ' + vdr_i['component']
    if(ovs['visible'] ): ovs['info']  = str(ovs_i['hopCount'] ) + ' ' + ovs_i['hostId']  + ' ' + ovs_i['component']
    if(vm1['visible'] ): vm1['info']  = str(vm1_i['hopCount'] ) + ' ' + vm1_i['hostId']  + ' ' + vm1_i['component']
    if(vm2['visible'] ): vm2['info']  = str(vm2_i['hopCount'] ) + ' ' + vm2_i['hostId']  + ' ' + vm2_i['component']
    if(dfw1['visible']): dfw1['info'] = str(dfw1_i['hopCount']) + ' ' + dfw1_i['hostId'] + ' ' + dfw1_i['component']
    if(dfw2['visible']): dfw2['info'] = str(dfw2_i['hopCount']) + ' ' + dfw2_i['hostId'] + ' ' + dfw2_i['component']

    with open('/var/www/bootcamp-fe/logicalplane.json', 'w') as outfile:
        json.dump(logic_data, outfile)
    
    switch_arr = traceflow_records[traceflow_id]['physical']
    with open('/var/www/bootcamp-fe/physicalplane_templete.json') as physicaljson_file:    
        physical_data = json.load(physicaljson_file)
    spine = physical_data[0]
    lleaf = spine['children'][0]
    rleaf = spine['children'][1]
    lvtep = lleaf['children'][0]
    rvtep = rleaf['children'][0]
    lvtep['name'] = 'Source VTEP'
    rvtep['name'] = 'Destination VTEP'
    spine['name'] = 'Spine Switch'
    lleaf['name'] = 'Source Leaf Switch'
    rleaf['name'] = 'Destination Leaf Switch'

    if (len(switch_arr) < 1):
        with open('/var/www/bootcamp-fe/physicalplane.json', 'w') as outfile:    
            json.dump({}, outfile)
    elif (len(switch_arr) < 2):
        lvtep['info'] = vtep_list[0]
        lleaf['info'] = switch_arr[0]['ip'] + ' ' + switch_arr[0]['hostname']
        spine['info'] = switch_arr[1]['ip'] + ' ' + switch_arr[1]['hostname']
        lvtep['visible'] = True
        lleaf['visible'] = True
        spine['visible'] = True
        rleaf['visible'] = False
        rvtep['visible'] = False
        with open('/var/www/bootcamp-fe/physicalplane.json', 'w') as outfile:    
            json.dump(physical_data, outfile)
    else:
        lvtep['info'] = vtep_list[0]
        lleaf['info'] = switch_arr[0]['ip'] + ' ' + switch_arr[0]['hostname']
        spine['info'] = switch_arr[1]['ip'] + ' ' + switch_arr[1]['hostname']
        rleaf['info'] = switch_arr[2]['ip'] + ' ' + switch_arr[2]['hostname']
        rvtep['info'] = vtep_list[1]
        lvtep['visible'] = True
        lleaf['visible'] = True
        spine['visible'] = True
        rleaf['visible'] = True
        rvtep['visible'] = True
        with open('/var/www/bootcamp-fe/physicalplane.json', 'w') as outfile:    
            json.dump(physical_data, outfile)

    flag = False
    inserted_result_1 = []
    inserted_result_2 = []
    inserted_result = []
    for node in result_arr:
        if (node['component'] == 'PHYS' and not node['compDisplayName'] == 'vNIC'):
            flag = True
        else:
            if (not flag):
                inserted_result_1.append(node)
            else:
                inserted_result_2.append(node)

    for node in inserted_result_1:
        inserted_result.append(node)

    for switch in switch_arr:
        nsx_node = {}
        nsx_node['component'] = 'PHYSWITCH'
        nsx_node['compDisplayName'] = switch['hostname']
        nsx_node['hostId'] = switch['ip']
        inserted_result.append(nsx_node)

    for node in inserted_result_2:
        inserted_result.append(node)

    info_data_str = "["
    for i in range(0, len(inserted_result) - 1):
        base_str = "{ \"Step\":\"" + str(i) + "\", \"Name\":\"" + inserted_result[i]['component'] + ' ' + inserted_result[i]['compDisplayName'] + "\", \"Info\":\"" + inserted_result[i]['hostId'] + "\"},"
        info_data_str = info_data_str + base_str
    i = len(inserted_result) - 1
    info_data_str = info_data_str + "{ \"Step\":\"" + str(i) + "\", \"Name\":\"" + inserted_result[i]['component'] + ' ' + inserted_result[i]['compDisplayName'] + "\", \"Info\":\"" + inserted_result[i]['hostId'] + "\"}]"
    with open('/var/www/bootcamp-fe/information.json', 'w') as outfile:    
            outfile.write(info_data_str)

    return Response(render_url, content_type='text/plain; charset=utf-8')

@app.route('/api/db/traceflow/one/<traceflow_id>', methods=['GET'])
def db_get_one_result(traceflow_id):
    global db_mgmt_info
    db = MySQLdb.connect(db_mgmt_info['ip'], db_mgmt_info['username'], db_mgmt_info['password'], db_mgmt_info['db'])
    conn = db.cursor()
    conn.execute('SELECT * FROM TRACEDATA')
    traceflow_data = conn.fetchall()
    data_row = {}
    for row in traceflow_data:
        if row[0] == traceflow_id:
            db_traceflow_id = row[0]
            data_row = pickle.loads(row[9])
    return jsonify(data_row)

@app.route('/api/db/traceflow', methods=['GET'])
def get_all_result():
    global db_mgmt_info
    db = MySQLdb.connect(db_mgmt_info['ip'], db_mgmt_info['username'], db_mgmt_info['password'], db_mgmt_info['db'])
    conn = db.cursor()
    conn.execute('SELECT * FROM TRACEDATA')
    traceflow_data = conn.fetchall()
    data_array = []
    for row in traceflow_data:
        db_traceflow_id = row[0]
        db_traceflow_data = pickle.loads(row[9])
        data_array.append({db_traceflow_id : db_traceflow_data})
    return jsonify({'data' : data_array})

@app.route('/api/db/traceflow/<batchid>', methods=['GET'])
def get_all_result_with_batch_id(batchid):
    global db_mgmt_info
    db = MySQLdb.connect(db_mgmt_info['ip'], db_mgmt_info['username'], db_mgmt_info['password'], db_mgmt_info['db'])
    conn = db.cursor()
    conn.execute('SELECT * FROM TRACEDATA')
    traceflow_data = conn.fetchall()
    data_array = []
    for row in traceflow_data:
        if row[8] == batchid:
            db_traceflow_id = row[0]
            db_traceflow_data = pickle.loads(row[9])
            data_array.append({db_traceflow_id : db_traceflow_data})
    return jsonify({'data' : data_array})

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    filterwarnings('ignore', category = MySQLdb.Warning)
    initialization()
    app.run(host='0.0.0.0', port=5000)
