import boto3
from pysnmp.entity.rfc3413.oneliner import cmdgen
from datadog import initialize, api
from os import environ
from base64 import b64decode

client = boto3.client('kms')
    
def parseFromRouter():
    data = []
    cmdGen = cmdgen.CommandGenerator()
    
    SNMP_HOST = environ.get('ROUTER_HOST')
    SNMP_PORT = 161
    SNMP_COMMUNITY = client.decrypt(CiphertextBlob=b64decode(environ.get('ROUTER_COMMUNITY_STRING')))['Plaintext']
    
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.nextCmd(
        cmdgen.CommunityData(SNMP_COMMUNITY),
        cmdgen.UdpTransportTarget((SNMP_HOST,  SNMP_PORT)),
        '1.3.6.1.2.1.2.2.1.2',
        '1.3.6.1.2.1.2.2.1.10',
        '1.3.6.1.2.1.2.2.1.16'
        )
        
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[-1][int(errorIndex)-1] or '?'
                )
            )
        else:
            for vb in varBinds:
                temp = []
                for name, val in vb:
                    temp.append(val.prettyPrint())
                data.append(temp)
    return data

def main(event, context):
    
    options = {
    'api_key': client.decrypt(CiphertextBlob=b64decode(environ.get('DATADOG_API_KEY')))['Plaintext'],
    'app_key': client.decrypt(CiphertextBlob=b64decode(environ.get('DATADOG_APP_KEY')))['Plaintext']
    }
    
    initialize(**options)
    data = parseFromRouter()
    
    print('Started send to datadog')
    
    for interface in data:
        interfaceTag = 'interface:%s' % interface[0]
        api.Metric.send([{
            'metric': 'metric-name.ifInOctets',
            'points': int(interface[1]),
            'host': 'hostname',
            'tags': interfaceTag
        }, {
            'metric': 'metric-name.ifOutOctets',
            'points': int(interface[2]),
            'host': 'hostname',
            'tags': interfaceTag
        }])
        
    print('Finished send to datadog')
    
    return data
