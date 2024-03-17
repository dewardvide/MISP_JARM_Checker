import requests
import argparse
import os 
import subprocess
import json

class MISP_Config:
    # Class attributes for MISP IP and Auth Key
    MISP_Ip = None
    MISP_Auth_Key = None

    @classmethod
    def set_config(cls, MISP_Ip, MISP_Auth_Key):
        # Set the class attributes with the provided values
        cls.MISP_Ip = MISP_Ip
        cls.MISP_Auth_Key = MISP_Auth_Key

    def __init__(self):
        # Load configuration from JSON file if class attributes are not set
        if not MISP_Config.MISP_Ip or not MISP_Config.MISP_Auth_Key:
            with open('config.json') as f:
                Config_Items = json.load(f)
        
            MISP_Config.set_config(Config_Items.get('MISP_IP'), Config_Items.get('MISP_AUTH_KEY'))
    
    def fetch_ip(self):
        ip = MISP_Config.MISP_Ip
        return ip
    
    def fetch_key(self):
        key = MISP_Config.MISP_Auth_Key
        return key 
 
class Object_Enrichment:

    def __init__(self, MISP_Config):
        self.MISP_Config = MISP_Config

    def get_attribute(self):
        MISP_Ip = self.MISP_Config.fetch_ip()
        MISP_Key = self.MISP_Config.fetch_key()
        #example event ID 
        Event_ID = input("Enter EventID: (1327)\n")
        Data = {
            'eventid' : '{}'.format(Event_ID), 
            #get IP addresses and domains attributes
            'type' : ["domain", "ip-src", "ip-dst", "hostname"]
        }
        Json_Data = json.dumps(Data)
        Url = 'https://'+MISP_Ip+'/attributes/restSearch'
        Headers = {"Authorization": "{}".format(MISP_Key), "Content-Type": "application/json"}
        
        #print headers (Testing)
        #print(Headers)
        #print(Json_Data)

        #SSL verification is false
        response = requests.post(Url, headers=Headers, data=Json_Data, verify=False)

        if response.status_code == 200:
            print("Request successful")
            return response.json()
        else:
            print("Request failed:", response.status_code)
            return response.text

    def enrichment(self):
        MISP_Ip = self.MISP_Config.fetch_ip()
        MISP_Key = self.MISP_Config.fetch_key() 
        #get attributes
        response = self.get_attribute()
        #print individual attributes
        for attribute in response['response']['Attribute']:
            values = attribute['value']
            attribute_id = attribute['id']
            #initiate subprocess to collect jarm fingerprints
            jarm_process = subprocess.run(['python3', 'jarm.py', '{}'.format(values)], capture_output=True, text=True)
            jarm_raw_data = jarm_process.stdout.strip()
            jarm_raw_data_lines = jarm_raw_data.splitlines()
            jarm = jarm_raw_data_lines[-1]
            #test
            print(values)
            print(attribute_id)
            print(jarm)
            #Add comment
            Data = {
            'comment' : '{}'.format(jarm), 
            }
            Json_Data = json.dumps(Data)
            Url = 'https://'+MISP_Ip+'/attributes/edit/{}'.format(attribute_id)
            Headers = {"Authorization": "{}".format(MISP_Key), "Accept": "application/json", "Content-Type": "application/json"}
            response = requests.post(Url, headers=Headers, data=Json_Data, verify=False)
            print(response.status_code)

class Change_Checker():
    #checks for changes in the JARM 
    def __init__(self, Object_Enrichment, MISP_Config):
        self.Object_Enrichment = Object_Enrichment
        self.MISP_Config = MISP_Config

    def checker(self): 
        #tag ID
        tag_Id = 1444
        MISP_Key = self.MISP_Config.fetch_key()
        MISP_Ip = self.MISP_Config.fetch_ip()

        # get attributes and filter out the value and comment - use value for JARM - use comment for comparison
        Attributes = self.Object_Enrichment.get_attribute()
        for attribute in Attributes['response']['Attribute']:
            values = attribute['value']
            attribute_id = attribute['id']
            comment = attribute['comment']
            #initiate subprocess to collect jarm fingerprints
            jarm_process = subprocess.run(['python3', 'jarm.py', '{}'.format(values)], capture_output=True, text=True)
            jarm_raw_data = jarm_process.stdout.strip()
            jarm_raw_data_lines = jarm_raw_data.splitlines()
            jarm = jarm_raw_data_lines[-1]

            if jarm != comment: 
                #tag ID 1444  
                Url = 'https://'+MISP_Ip+'/attributes/addTag/{0}/{1}'.format(attribute_id, tag_Id)
                Headers = {"Authorization": "{}".format(MISP_Key), "Accept": "application/json", "Content-Type": "application/json"}
                response = requests.post(Url, headers=Headers, verify=False)
                print(response.json())
                print("Changes in JARM Signature found and the tag has been appplied to AttributeId: {0} Value {1}".format(attribute_id, values))
            else: 
                print("Changes in JARM Signature for AttributeId: {} have NOT been identified".format(attribute_id))

def update():
    download_status = ''
    update_response = requests.get('https://raw.githubusercontent.com/salesforce/jarm/master/jarm.py')

    if update_response.status_code == 200:
        with open('jarm.py', 'wb') as f:
            f.write(update_response.content)
            download_status =  print("Update Complete")
    else: 
        download_status = print("Update Failed. Status Code: ", update_response.status_code)

    return download_status

def main(): 
    # Create ArgumentParser object
    parser = argparse.ArgumentParser(description='IOC EOL CHECKER => Analyze Changes in the JARM signature in MISP Objects')

    # Add arguments
    parser.add_argument('-u', '--update', action='store_true', help='Update JARM.')
    parser.add_argument('-e', '--enrich', action='store_true', help='Use this flag to enrich attributes in a particular event.')
    parser.add_argument('-c', '--change_check', action='store_true', help='Use this flag to check for changes in a particular event.')
    
    #create an instance of the class
    misp_c = MISP_Config()
    o_e = Object_Enrichment(misp_c)
    c_c = Change_Checker(o_e, misp_c)

    # Parse the command-line arguments
    args = parser.parse_args()

    #return usage where flags are not used
    if not any(vars(args).values()):
        parser.print_usage()
        return
    
    # Access the arguments
    if args.update: 
        update()

    if args.enrich:
        print("MISP IP: "+misp_c.fetch_ip())
        print(o_e.enrichment())
    
    if args.change_check:
        print("MISP IP: "+misp_c.fetch_ip())
        print(c_c.checker())
        
if __name__ == "__main__":
    main()

