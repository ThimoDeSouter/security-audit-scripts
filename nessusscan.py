import requests
import json
import datetime
import time
import sys
import getpass
import os
import subprocess

from scan import Scan

verify = False
token = None

url = None
username = None
password = None

scans = []

outputdir = os.environ['HOME']+'/Desktop/audit-scans/'

if not os.path.exists(outputdir):
        print 'creating output dir:'
        print outputdir
        os.makedirs(outputdir)


today = datetime.date.today()

day = str(today.day)
if(len(day) == 1): day = "0"+day

month = str(today.month)
if(len(month) == 1): month = "0"+month

timestamp = ( str(today.year) + '-' + str(month) + '-' + str(day))


def build_url(resource):
    return '{0}{1}'.format(url, resource)

def connect(method, resource, data=None):

    headers = {'X-Cookie': 'token={0}'.format(token),'content-type': 'application/json'}

    data = json.dumps(data)

    if method == 'POST':
        r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'PUT':
        r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
    elif method == 'DELETE':
        r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
    else:
        r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

    if r.status_code != 200:
        e = r.json()
        print e['error']
        sys.exit()

    if 'download' in resource:
        return r.content
    else:
	try:
        	return r.json()
	except:
		print 'an error occured'



def login(username, password):
	login = {'username': username, 'password': password}
	data = connect('POST', '/session', data=login)
	return data['token']


def logout():
	connect('DELETE', '/session')


def get_policies():
	data = connect('GET', '/editor/policy/templates')
	return dict((p['title'], p['uuid']) for p in data['templates'])


def get_history_ids(sid):
	data = connect('GET', '/scans/{0}'.format(sid))
	return dict((h['uuid'], h['history_id']) for h in data['history'])


def get_scan_history(sid, hid):
	params = {'history_id': hid}
	data = connect('GET', '/scans/{0}'.format(sid), params)
	return data['info']


def add(name, desc, targets, pid):
    scan = {'uuid': pid,
            'settings': {
                'name': name,
                'description': desc,
                'text_targets': targets}
            }

    data = connect('POST', '/scans', data=scan)
    return data['scan']


def update(scan_id, name, desc, targets, pid=None):
    scan = {}
    scan['settings'] = {}
    scan['settings']['name'] = name
    scan['settings']['desc'] = desc
    scan['settings']['text_targets'] = targets

    if pid is not None:
        scan['uuid'] = pid

    data = connect('PUT', '/scans/{0}'.format(scan_id), data=scan)
    return data


def launch(sid):
    data = connect('POST', '/scans/{0}/launch'.format(sid))
    return data['scan_uuid']


def status(sid, hid):
    stat = get_scan_history(sid, hid)
    return stat['status']


def export_status(sid, fid):
    data = connect('GET', '/scans/{0}/export/{1}/status'.format(sid, fid))
    return data['status'] == 'ready'


def export(sid, hid):
    data = {'history_id': hid,
            'format': 'nessus'}

    data = connect('POST', '/scans/{0}/export'.format(sid), data=data)

    fid = data['file']

    while export_status(sid, fid) is False:
        time.sleep(5)

    return fid


def download(sid, fid,name):
    data = connect('GET', '/scans/{0}/export/{1}/download'.format(sid, fid))
    filename = str(timestamp) + "-" +  str(name)  + ".nessus"

    print("Saving scan results to: " +  str(outputdir)+str(filename))
    with open(outputdir+filename, 'w') as f:
        f.write(data)


def delete(sid):
    connect('DELETE', '/scans/{0}'.format(scan_id))


def history_delete(sid, hid):
    connect('DELETE', '/scans/{0}/history/{1}'.format(sid, hid))

def create_scan(scans):
	print ('\n')
	print 'Adding new scan:\n'
	policies = get_policies()
	policy_id = policies['Basic Network Scan']
	scan_name = raw_input("Scan name: ")
	scan_targets = raw_input("Targets: ")
	scan_description = raw_input("Description: ")
	scan_data = add(scan_name, scan_description, scan_targets, policy_id)
	scan_id = scan_data['id']

	scan = Scan(scan_name,scan_description,scan_targets,scan_id)
	scans.append(scan)

def show_scans(scans):
	for scan in scans:
		print 'Name: ' + str(scan.name) + ',  Target(s): ' + str(scan.targets)


def launch_scans(scans):
	for scan in scans:
		print('Launching scan: ' + str(scan.name))
		scan_uuid = launch(scan.id)
		history_ids = get_history_ids(scan.id)
		history_id = history_ids[scan_uuid]
		scan.setHistory_id(history_id)

def incomplete(scans):
	incomplete = True
	for scan in scans:
		if (status(scan.id, scan.history_id) != 'completed'):
			incomplete = True
			break
		else:
			incomplete = False
	return incomplete

def view_status_scans(scans):
	os.system('clear')
	for scan in scans:
		print scan.name + " = " + status(scan.id, scan.history_id)

	count = 20
	while(count >=0):
    		sys.stdout.write("\rRefresh in:{0}>>".format(count))
    		sys.stdout.flush()
		count -=1
    		time.sleep(1)

if __name__ == "__main__" :


	print 'Welcome to the nessus scan tool'

	#start nessus
	print ("starting nessus")
	command="/etc/init.d/nessusd start > /dev/null"
        proc = subprocess.Popen([command],stdout=subprocess.PIPE,shell=True)
        out = proc.communicate()


	print 'gathering variables:'
	username = raw_input("Nessus Username: ")
	password = getpass.getpass("Nessus Password: ")

	url = raw_input("Nessus URL (blank for 'https://localhost:8834'): ")
	if ( url == ''):
		url = "https://localhost:8834"


	print('Logging in...')
	token = login(username, password)
	#TODO: validate login result

	create_scan(scans)
	while True:
		print 'current scans in queue: '
		show_scans(scans)
		cont = raw_input("Add another scan? (y/n): ")
		if (cont == 'y'):
			create_scan(scans)
		else:
			break

	print ('The scans will be launched now.')
	launch_scans(scans)

	while (incomplete(scans)):
		view_status_scans(scans)

	print '\n'
	print('Exporting the completed scans...')
	for scan in scans:
		file_id = export(scan.id, scan.history_id)
		download(scan.id, file_id,scan.name)



