import requests
import argparse
import os 

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
    parser.add_argument('-f', '--flag', action='store_true', help='Description of the flag.')

    # Parse the command-line arguments
    args = parser.parse_args()

    #return usage where flags are not used
    if not any(vars(args).values()):
        parser.print_usage()
        return
    
    # Access the arguments
    if args.update: 
        update()

    if args.flag:
        print("Flag is set.")
        
if __name__ == "__main__":
    main()

