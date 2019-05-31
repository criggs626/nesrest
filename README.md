# Nesrest
This is a python library designed to make interacting with the nessus API easy and conveinent. The library consists of a single python class that has three main sections. The first section is custom functions that are designed for making simple operations easier to completed. Operations like downloaded a file can be done in one step instead of several. The next section is full API integration. Functions that simply interact with the Nessus API and return logical results. The final section is functions designed to do the interaction work such as get and post.

## Custom functions
#### Download Scan
The download scan function will take a scan ID number and download the scan as a CSV named after the unique token that gets generated during this processes. It has a second input of the time in seconds you would like to wait for the scan to get generated before ending.
```python
result = nessus.downloadScan(330,30)
print(result)
```
#### Download Raw
The download raw function is the same as download scan except you get the raw of the file instead of saving the file by token name.
```python
result = nessus.downloadRaw(330,30)
print(result)
```
#### Print Scan Summary
Print a useful summary of the scan, each host and the number of vulnerabilities found per host given the scan id number as an input
```python
result = nessus.printScanSummary(330)
```
#### Output scan for Splunk
Like many of you lovely people out there we use a lot of Splunk at our company. Because of this we wanted to be able to output nessus scan data into Splunk. This function returns a string giving the details of a scan in a good format to upload to Splunk. The result includes JSON data for each host, that json has the host name, scan name, time, vulnerability count, and detailed vulnerabilities. The detailed vulnerabilities includes the plugin family, plugin name, plugin output, plugin id, and plugin details. Each host can have multiple vulnerabilities. Example of how to use this is shown below. Pro tip, set when configuring the source type set **add the TRUNCATE variable and set it to 20,000** or so. Scan outputs are big.
```python
textOutput = nessus.outputForSplunk(330)
```

## API functions
The following functions are listed by their name in the nessus API documentation and what they are called in this library. Some of them are named differently because I thought it made more sense. Disagree? Oh well.

### Folders
#### folders:list => nessus.folder.list()
Returns a list of folders from your system.

### Scans
#### scans:list => nessus.scan.list() && nessus.scan.list(folderID)
Get scans returns a list of all scans from your system.
Get scans from folder returns a list of all scans in a folder given the unique folderID.

#### scans:details => nessus.scan.details(scanID)
Get details of a scan given the scanID.

#### scans:host-details => nessus.scan.hostDetails(scanID,hostID)
Get details of a host given the scanID and hostID.

#### scans:plugin-output => nessus.scan.pluginDetails(scanID,hostID,pluginID)
Returns the plugin details for the given host in the context of a scan.

#### scans:export-request => nessus.scan.exportRequest(scanID)
Starts an export request given a scanID and returns the token.

### Tokens
#### tokens:status => nessus.token.status(token)
Returns the message status of a given token.

#### tokens:download => nessus.token.download(token)
Downloads the file given a token, returns with a message indicating the download status.

#### tokens:download => nessus.token.downloadRaw(token)
Returns the raw file given a token.

### Policies
There was stuff and functions added for policies, turns out you need security center for that. As such documenting these changes aren't a priority for your average nessus pro user like me. They'll get documented eventually but for now the functions are relatively straight forward.

## Examples
```python
from nesrest import Nessus
accessKey = "Your Access Key"
secretKey = "Your Secret Key"
baseURL = "http://Your URL"
nessus = Nessus(accessKey, secretKey, baseURL)

# Get folders
folders = nessus.folder.list()

# Get scans
scans = nessus.scan.list()

scanID = 0
# Get scan details
details = nessus.scan.details(scanID)

# Splunk output
splunkOutput = nessus.outputForSplunk(scanID)
```
## Graphical Downloader
The graphical downloader is a working example of something that can be done using the Nessus library. It uses tkinter to create a gui that lets anyone download scan results.
## Monitor for Splunk
This python file is another working demo to show how you can output folders for Splunk. The script makes it's own config that tracks when a scan was last modified and will only update the log if the scan has been run again. The results of this script are written to a log which can be monitored by Splunk or forwarded however you'd like. Now I know what you're thinking "Why don't we just use the Splunk app", well if your scanner is behind firewalls you can use this script and syslog to send it out, and personally I like my JSON formatted output better than the default one. It is much more readable and allows quicker action on scan results. PS. use a cron job or something to schedule this script to run.
