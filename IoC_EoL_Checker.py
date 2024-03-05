import requests
import argparse
#import jarm
import os 
import subprocess
import json

class MISP:
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
        if not MISP.MISP_Ip or not MISP.MISP_Auth_Key:
            with open('config.json') as f:
                Config_Items = json.load(f)
        
            MISP.set_config(Config_Items.get('MISP_IP'), Config_Items.get('MISP_AUTH_KEY'))
    
    def print_test(self):
        print(MISP.MISP_Ip)
        print(MISP.MISP_Auth_Key)
 
def Object_Enrichment(): 
    return 

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
    parser.add_argument('-t', '--test', action='store_true', help='Used for testing.')
    

    # Parse the command-line arguments
    args = parser.parse_args()

    #return usage where flags are not used
    if not any(vars(args).values()):
        parser.print_usage()
        return
    
    # Access the arguments
    if args.update: 
        update()

    if args.test:
        misp_i = MISP()
        misp_i.print_test()
        
if __name__ == "__main__":
    main()

