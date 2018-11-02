## Nesrest
This is a python library designed to make interacting with the nessus API easy and conveinent. The library consists of a single python class that has three main sections. The first section is custom functions that are designed for making simple operations easier to completed. Operations like downloaded a file can be done in one step instead of several. The next section is full API integration. Functions that simply interact with the Nessus API and return logical results. The final section is functions designed to do the interaction work such as get and post.

### Custom functions
#### Download Scan
The download scan function will take a scan ID number and download the scan as a CSV named after the unique token that gets generated during this processes. It has a second input of the time in seconds you would like to wait for the scan to get generated before ending.
```python
result = nessus.downloadScan(330,30)
print(result)
```
#### Print Scan Summary
Print a useful summary of the scan, each host and the number of vulnerabilities found per host given the scan id number as an input
```python
result = nessus.printScanSummary(330)
```
#### Output scan for Splunk
Like many of you lovely people out there we use a lot of Splunk at our company. Because of this we wanted to be able to output nessus scan data into Splunk. This function returns a string giving the details of a scan in a good format to upload to Splunk. The result includes JSON data for each host, that json has the host name, scan name, time, vulnerability count, and detailed vulnerabilities. The detailed vulnerabilities includes the plugin family, plugin name, plugin output, plugin id, and plugin details. Each host can have multiple vulnerabilities. Example of how to use this is shown below.
```python
textOutput = nessus.outputForSplunk(330)
```

### API functions
The following functions are listed by their name in the nessus API documentation and what they are called in this library. (Why named differently? Because I didn't really think of that until now so this is just gonna be our lives now)

#### folders:list => getFolders()
Returns a list of folders from your system.

#### scans:list => getScans() && getScansFromFolder(folderID)
Get scans returns a list of all scans from your system.
Get scans from folder returns a list of all scans in a folder given the unique folderID.

#### scans:details => getScanDetails(scanID)
Get details of a scan given the scanID.

#### scans:host-details => getHostDetails(scanID,hostID)
Get details of a host given the scanID and hostID.

#### scans:export-request => exportRequest(scanID)
Starts an export request given a scanID and returns the token.

#### tokens:status => getTokenStatus(token)
Returns the message status of a given token.

#### tokens:download => getTokenDownload(token)
Downloads the file given a token, returns with a message indicating the download status.

#### scans:plugin-output => getScanPluginDetails(scanID,hostID,pluginID)
Returns the plugin details for the given host in the context of a scan.
