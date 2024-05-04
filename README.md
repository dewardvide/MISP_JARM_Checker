
# MISP JARM Checker

A python script to enrich your MISP attributes with JARM signatures and check for changes in the attribute's JARM signatures. 

## What is JARM?

JARM is a fingerprinting tool that takes advantage of certain aspects of the TLS network security protocol to produce a hybrid fuzzy hash that can be used to identify a server. 

## Why did I do this?

This project is an extension of an investigation I did for my Bachelor's thesis whose aim was to "Investigating the Use of TLS Fingerprinting to Identify End of Life Indicators of Compromise Through Automation".

#### ...So, what did you discover in your research?

JARM is a fuzzy hash so it should not be an independent source of truth when trying to identify a server. Therefore, when it comes to the identification of EOL IoCs through changes in JARM signatures, these changes should be considered in a larger IoC/attribute scoring system such as the MISP IoC decay system (explained in this [Paper](https://arxiv.org/abs/1902.03914)).

## Documentation

Below is a UML sequence diagram that explains the functioning of the code. 

<img width="452" alt="image" src="https://github.com/dewardvide/MISP_JARM_Checker/assets/91884298/436743c4-216b-4af7-8a7c-f1ecdba982cd">

## Deployment

Step 1 Acquire and install the prerequisites 

```bash
  MISP Server and MISP API Authorization Key
  Python 3.0 and above 
```
(The JARM tool is included in the repository) 

Step 2 Clone the repository and navigate to the repository on your local machine

Step 3 Add your MISP server IP address and Authorization key to config.json 

Step 4 Run the script 

```bash
  MISP_JARM_Checker.py -h
  usage: MISP_JARM_Checker.py [-h] [-u] [-e <Event_ID>] [-c <Event_ID> <Tag_ID>]

  MISP JARM Checker => Analyze Changes in the JARM signature in MISP Objects

options:
  -h, --help            show this help message and exit
  -u, --update          Update JARM.
  -e <Event_ID>, --enrich <Event_ID>
                        Use this flag to enrich attributes in a particular event.                   
  -c <Event_ID> <Tag_ID>, --change_check <Event_ID> <Tag_ID>
                        Use this flag to check for changes in a particular event.
```
  



## Authors

- David N. Omurwa [@dewardvide](https://github.com/dewardvide)


## Acknowledgements

 - [The MISP project](https://www.misp-project.org/)



## Installation

Install my-project with npm

```bash
  npm install my-project
  cd my-project
```
    
