import json
from zipfile import ZipFile
import time
import requests
import os
import matplotlib.pyplot as plotter
from collections import OrderedDict

#Enter API key here ##########################################################
api_key = '***REMOVED***'
# Is your API key premium? This restricts access to EXIF output data.
premiumAPI = False
##############################################################################

# Customise the scan output by changing the included AV names here. This IS
antiviruses = {'Avast', 'AVG', 'BitDefender', 'FireEye', 'F-Secure', 'Malwarebytes', 'McAfee', 'Microsoft'}
##########################################################################

#Enter the location of your .ZIP file here #############################
filePath = "C:/Users/Ryan/Documents/Cowrie/payloads.zip"
########################################################################

with ZipFile(filePath, 'r') as zipObj:
    # Extract all the contents of zip file in different directory
    hashList = zipObj.namelist()

print('Scanning ZIP file: {0}'.format(filePath))
print('{0} files found.'.format(len(hashList)))
print('Your customised Antivirus engine outputs are:',
      ', '.join([str(av) for av in antiviruses]))
print('Scan commencing in 5 seconds.')
time.sleep(5)

print('\n##############################################################################################################\n')
payloadNo = 0

# Scan statistics tracking class


class Stats:
    def __init__(self):
        self.positiveResult = 0
        self.negativeResult = 0
        self.noResult = 0
        self.extensionsFound = {}

    positiveResult = 0
    negativeResult = 0
    noResult = 0
    extensionsFound = {}


try:
    for payload in hashList:
        payloadNo += 1
        # Makes request to virustotal to scan file
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': api_key, 'resource': payload, 'allinfo': 1}
        try:
            response = requests.get(url, params=params)
            vt_response = response.json()
        except BaseException:
            if response.status_code == 204:
                # Handles the 204 response code
                print(
                    'Recieved HTTP Response Code:',
                    response.status_code,
                    '-- Indicates that API usage quota has been used up.\nRefer to the VirusTotal API documentation for error description.\nDocumentation link: https://developers.virustotal.com/reference#api-responses')
                break
            print('An interrupt or error has occured.')
            break

        # Parsing the JSON response
        print(
            'Scanning Payload {0}/{1}: {2}'.format(payloadNo, len(hashList), payload))
        if vt_response['response_code'] == 1:
            print('Scan initiated at', vt_response['scan_date'])
            # Doesn't post AV results if there are zero positive results
            if vt_response['positives'] == 0:
                print('\nAll scans returned negative.')
                Stats.negativeResult += 1
            else:
                print('=== Antivirus Results ===')
                # Loops through selected AVs for detection results
                for av in antiviruses:
                    try:
                        print(
                            av,
                            '-> Detected:',
                            vt_response['scans'][av]['detected'],
                            ' Result:',
                            vt_response['scans'][av]['result'])
                    except KeyError:
                        # AVs included in 'antiviruses' might not always return
                        # scan results, which will cause a TypeError
                        print(av, 'could not return any test results.')
                Stats.positiveResult += 1

            # Standard scan result output
            print('\n=== Scan Results ===')
            if "total" in vt_response:
                print('Total Scans:', vt_response['total'])
            if "positives" in vt_response:
                print('Total Positive Results:', vt_response['positives'])
            if "first_seen" in vt_response:
                print('First seen:', vt_response['first_seen'])
            if "times_submitted" in vt_response:
                print('Times Submitted:', vt_response['times_submitted'])
            if "permalink" in vt_response:
                print('Scan Permalink: ', vt_response['permalink'])
            print('\n')

            # Attempts to output any EXIF data returned from the API
            try:
                if premiumAPI:
                    print('=== EXIF Data provided by https://exiftool.org/ ===')
                    if "additional_info" not in vt_response:
                        print("No EXIF information is available for this file.")
                    else:
                        print(
                            'File Type/Extension: {} (.{})'.format(
                                vt_response['additional_info']['exiftool']['FileType'],
                                vt_response['additional_info']['exiftool']['FileTypeExtension']))
                        # Retrieves the extension type and the number of occurances
                        # If the extension is not already stored then it is added with
                        # default value of 0
                        extension = Stats.extensionsFound.get(vt_response['type'], 0)
                        extension += 1
                        Stats.extensionsFound[vt_response['type']] = extension

                        print('File Size:', round(
                            vt_response['size'] / 1024 / 1024, 2), 'MB')
                        print('Description:', vt_response['additional_info']['magic'])
                        print(
                            'Target Operating System:',
                            vt_response['additional_info']['exiftool']['OperatingSystem'])

            # Not every EXIF data field is returned by the API, which is
            # handled below.
            except KeyError as err:
                print('\nSome EXIF data was not found :(\n')

        # Handles other response codes:
        # https://developers.virustotal.com/reference#api-responses
        elif vt_response['response_code'] != 1:
            print(
                '===========================================================================\n',
                vt_response['verbose_msg'],
                '\n===========================================================================')
            Stats.noResult += 1
        print('\n##############################################################################################################\n')

        # Sleeps script to comply with API user agreement
        # Set to 15 for public API, 4.5 for Academic/Premium API
        time.sleep(15)

# Generic exception handling :/
except KeyboardInterrupt:
    print('Keyboard Interrupt')

# Show intersting scan stats
print('=== Scan Report ===')
print('{0} files were scanned'.format(payloadNo))
print(
    '{0} positive matches were found for malicous files'.format(
        Stats.positiveResult))
print('{0} negative matches were found for malicous files'.format(
    Stats.negativeResult))
print('{0} scans had no result due to files still being analysed.'.format(
    Stats.noResult))
print('\nList of different file extensions found from successful scans:')

# Show each file extension found
sortedExtensions = OrderedDict(
    sorted(Stats.extensionsFound.items(), key=lambda x: x[1], reverse=True))
for ext in sortedExtensions:
    print('   {0}: {1}'.format(ext, sortedExtensions[ext]))

# Graphing
print('\n=== Graph Report ===')
print('Once created, you can customise the graph in the matplotlib GUI.\n')
x_data = []
extensionFreq = []

for ext in sortedExtensions:
    x_data.append(ext)
    extensionFreq.append(sortedExtensions[ext])
x_pos = [i for i, _ in enumerate(x_data)]
rects = plotter.bar(x_pos, extensionFreq, color='#621360',
                    align='center', width=0.4)
# Annotates the top of each bar with its value
for rect in rects:
    height = rect.get_height()
    plotter.annotate('{}'.format(height),
                     xy=(rect.get_x() + rect.get_width() / 2,
                         height),
                     xytext=(0,
                             3),
                     textcoords="offset points",
                     ha='center',
                     va='bottom')
plotter.xlabel('Extension type')
plotter.ylabel('Frequency')
plotter.title('File extensions found inside {0}'.format(
    filePath), bbox={'facecolor': '0.8', 'pad': 5}, y=1.08)
plotter.xticks(x_pos, x_data)
plotter.figure(figsize=(25, 3), dpi=300)
plotter.rcParams['figure.facecolor'] = 'white'
# Opens the matplotlib GUI
try:
    plotter.show()
except BaseException:
    print("Error with plotter")
print('Scan complete')
