import requests
import json
import time
import datetime
requests.packages.urllib3.disable_warnings()

class Nesrest:
    # Initialize the nesrest class
    def __init__(self, akey, skey, url):
        self.akey = akey
        self.skey = skey
        self.baseURL = url
        self.header = {"X-ApiKeys" : "accessKey=" + self.akey + ";secretKey=" + self.skey +";"}

    ###
    # Custom Functions
    # These functions use the API to add more intuitive functionality
    ###
    # Download a scans results given the ID
    def downloadScan(self,scanID,waitTime):
        token = self.exportRequest(scanID)
        for i in range(0,waitTime):
            response = self.getTokenStatus(token)
            if(response == "The download is ready."):
                response = self.getTokenDownload(token)
                return response
            time.sleep(1)

    # Download a scans results given the ID
    def downloadRaw(self,scanID,waitTime):
        token = self.exportRequest(scanID)
        for i in range(0,waitTime):
            response = self.getTokenStatus(token)
            if(response == "The download is ready."):
                response = self.getTokenDownloadRaw(token)
                return response
            time.sleep(1)

    # Print a scans summary
    def printScanSummary(self,scanID):
        scan = self.getScanDetails(scanID)
        print("Host\t\tVulns.")
        print("-------------------------------------")
        for host in scan["hosts"]:
            id = host["host_id"]
            hostDetails = self.getHostDetails(scanID, id)
            print(hostDetails["info"]["host-ip"] + "\t" + str(len(hostDetails["vulnerabilities"])))

    # Return string output of scan details optimized for splunk
    def outputForSplunk(self,scanID):
        output = ""
        details = self.getScanDetails(scanID)
        scanName = details["info"]["name"]
        scanTime = datetime.datetime.fromtimestamp(details["info"]["scan_end"]).strftime('%Y-%m-%d %H:%M:%S')
        for host in details["hosts"]:
            name = host["hostname"]
            item={"scan":scanName,"time":scanTime,"hostname":name}
            hostDetails = self.getHostDetails(scanID,host["host_id"])
            vulns = []
            count = 0
            for vuln in hostDetails["vulnerabilities"]:
                temp = {}
                temp["severity"] = vuln["severity"]
                temp["plugin_family"] = vuln["plugin_family"]
                temp["plugin_name"] = vuln["plugin_name"]
                temp["plugin_id"] = vuln["plugin_id"]
                pluginDetails = self.getScanPluginDetails(scanID,host["host_id"],vuln["plugin_id"])
                pluginOutput = pluginDetails["outputs"][0]["plugin_output"]
                try:
                    if (len(pluginOutput) > 800):
                        temp["details"] = "Output to long to display"
                    else:
                        temp["details"] = pluginOutput
                except:
                    temp["details"] = "No Output"
                vulns.append(temp)
                count += 1

            item["vulns"] = vulns
            item["vulnCount"] = count
            output += json.dumps(item)+"\n"
        return output

    ###
    # API Functions
    # These functions interact with the API and return the logical results
    ###
    # Return a list of folders
    def getFolders(self):
        response = self.getRequest("folders",0)
        return response["folders"]

    # Return a list of scans
    def getScans(self):
        response = self.getRequest("scans",0)
        return response["scans"]

    # Return a list of scans from a folder given folderID
    def getScansFromFolder(self,folderID):
        response = self.getRequest("scans",{"folder_id":folderID})
        return response["scans"]

    # Return a list of scans from a folder given folderID
    def getScanDetails(self,scanID):
        response = self.getRequest("scans/"+str(scanID),0)
        return response

    # Return a list of scans from a folder given folderID
    def getHostDetails(self,scanID,hostID):
        response = self.getRequest("scans/"+str(scanID)+"/hosts/"+str(hostID),0)
        return response

    # Request a scan export
    def exportRequest(self,scanID):
        response = self.postRequest("scans/"+str(scanID)+"/export",{"format":"csv"})
        return response["token"]

    # Return the status of a given token
    def getTokenStatus(self,token):
        response = self.getRequest("tokens/"+str(token)+"/status/",0)
        return response["message"]

    # Return the file from a given token
    def getTokenDownload(self,token):
        response = self.download("tokens/"+str(token)+"/download/",str(token))
        return response

    # Return the file from a given token
    def getTokenDownloadRaw(self,token):
        response = self.getRequest("tokens/"+str(token)+"/download/",1)
        return response

    # Return Plugin details per scan
    def getScanPluginDetails(self,scanID,hostID,pluginID):
        response = self.getRequest("scans/"+str(scanID)+"/hosts/"+str(hostID)+"/plugins/"+str(pluginID),0)
        return response

    ###
    # Functions to be used by the class itself
    # These functions are focused on HTTP requests
    ###
    # Get request
    def getRequest(self,endpoint,data):
        if(type(data) is dict):
            req = requests.get(self.baseURL+"/"+endpoint, headers=self.header, params=data, verify=False)
            res = json.loads(req.text)
            return res
        elif data == 0:
            req = requests.get(self.baseURL+"/"+endpoint, headers=self.header, verify=False)
            res = json.loads(req.text)
            return res
        elif data == 1:
            req = requests.get(self.baseURL+"/"+endpoint, headers=self.header, verify=False)
            res = req.text
            return res

    # Post request
    def postRequest(self,endpoint,data):
        if(type(data) is dict):
            req = requests.post(self.baseURL+"/"+endpoint, headers=self.header, data=data, verify=False)
            res = json.loads(req.text)
            return res
        else:
            req = requests.post(self.baseURL+"/"+endpoint, headers=self.header, verify=False)
            res = json.loads(req.text)
            return res

    # To download a file
    def download(self,endpoint,token):
        try:
            r = requests.get(self.baseURL+"/"+endpoint, headers=self.header, verify=False)
            with open(token+".csv", 'wb') as f:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk: # filter out keep-alive new chunks
                        f.write(chunk)
                        #f.flush() commented by recommendation from J.F.Sebastian
            return "Download complete"
        except:
            return "Unknown error"
