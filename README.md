# VirusTotal API Payload Scanner

# Analysing Honeypot Payloads with the VirusTotal API

Any files that are given to this script in a .ZIP file will be indivually sent to VirusTotal for scanning using [their v2 API](https://developers.virustotal.com/reference).

# Features
1. Displays scan reports from over [70 different Antivirus products](https://support.virustotal.com/hc/en-us/articles/115002146809-Contributors).
2. Creates a file extension summary graph of all payloads scanned.
3. Provides a URL to each indivudual scan performed.
4. Provides statitistics on total scans performed and total positive results.
5. Ideal for analysis of malicious files collected through honeypots.
6. API usage quota detection
7. Customisability option to only display results from specified Antivirus engines.

# Prerequesites
1. Python 3+
2. [Requests](https://requests.readthedocs.io/en/master/) module
3. [Matplotlib](https://matplotlib.org/) module
4. PyQt5 module
5. [OrderedDict](https://docs.python.org/3/library/collections.html#collections.OrderedDict) the [collections](https://docs.python.org/3/library/collections.html) module

# How to use
1. To use this script for yourself you will need to obtain a free public API key by [creating an account on the VirusTotal website](https://www.virustotal.com/gui/join-us).
2. Provide your API key, see below:

  ```
  #Enter API key here ########
  api_key = '<API KEY HERE>' #
  ############################
  ```
3. You must specifiy whether you have access to the premium API. Certain functionality of this script is dependant on access to the Academic/Premium API. 
    ```
    # Is your API key premium? This restricts access to EXIF output data.
    premiumAPI = False
    ```
4. Enter the file path of the ZIP file you wish to use, see below. Note that this script does not handle nested file structures. All files MUST be in the root folder of the ZIP.
```
  #Enter the location of your .ZIP file here #
  filePath = '<FILE PATH HERE>'              #
  ############################################
```
5. Choose the antivirus (AV) partners to include in the scan output. The default configuration includes Avast, AVG, BitDefender, FireEye, F-Secure, McAfee and Microsoft in the specific scan result output. This **IS** case sensitive.
```
# Customise the scan output by changing the included AV names here. This IS case and space sensitive.
antiviruses = {'Avast', 'AVG', 'BitDefender', 'FireEye','F-Secure', 'Malwarebytes', 'McAfee', 'Microsoft'}
```
6. Run the script and enjoy the sexy Antivirus results - Happy Virus Hunting!
"""