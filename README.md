# Analysing Honeypot Payloads with the VirusTotal API

Any files that are given to this script in a .ZIP file will be indivually sent to VirusTotal for scanning using [their v2 API](https://developers.virustotal.com/reference).

# Features



1. Displays scan reports from over [70 different Antivirus products](https://support.virustotal.com/hc/en-us/articles/115002146809-Contributors).
2. Provides a URL to each indivudual scan performed.
3. Provides statitistics on total scans performed and total positive results.
4. Ideal for analysis of malicious files collected through honeypots.
5. Basic API quota usage detection
6. Option to show scan results from specific Antivirus scanners instead of an overall summary.

# Prerequesites

1. Python
2. [Requests](https://requests.readthedocs.io/en/master/) module

# How to use

1. To use this script for yourself you will need to obtain a free public API key by [creating an account on the VirusTotal website](https://www.virustotal.com/gui/join-us).
2. Enter your API key on line 8, see below:

  ```
  #Enter API key here ########
  api_key = '<API KEY HERE>' #
  ############################
  ```
3. Enter the file path of the ZIP file you wish to use on line 16, see below:
```
  #Enter the location of your .ZIP file here ######
  with ZipFile('<FILE PATH HERE>', 'r') as zipObj:#
  #################################################
```
4. Line 12 contains a dictionary of Antivirus (AV) names to include in the scan output. Add or remove Antivirus names from this dictionary as you please. The default configuration will include Avast, AVG, BitDefender, FireEye, F-Secure, McAfee and Microsoft in the specific scan result output. This **IS** case sensitive.
```
#Customise the scan output by changing the included AV names here. This IS case and space sensitive.
antiviruses = {'Avast', 'AVG', 'BitDefender', 'FireEye', 'F-Secure', 'Malwarebytes', 'McAfee', 'Microsoft'}
```
5. Run the script and enjoy the sexy Antivirus results - Happy Virus Hunting!

## Example Output
![Example Output](https://iili.io/Jlanb2.jpg)
