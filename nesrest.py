import requests
import json
import time
import datetime
requests.packages.urllib3.disable_warnings()

class Nessus:
    # Initialize the nesrest class
    def __init__(self, akey, skey, url):
        self.scan = Scanner(akey, skey, url)
        self.folder = Folder(akey, skey, url)
        self.token = Token(akey, skey, url)
        self.policy = Policy(akey, skey, url)
        self.plugin = Plugin(akey, skey, url)

    ###
    # Custom Functions
    # These functions use the API to add more intuitive functionality
    ###
    # Download a scans results given the ID
    def downloadScan(self,scanID,waitTime):
        token = self.scan.exportRequest(scanID)
        for i in range(0,waitTime):
            response = self.token.status(token)
            if(response == "The download is ready."):
                response = self.token.download(token)
                return response
            time.sleep(1)

    # Download a scans results given the ID
    def downloadRaw(self,scanID,waitTime):
        token = self.scan.exportRequest(scanID)
        for i in range(0,waitTime):
            response = self.token.status(token)
            if(response == "The download is ready."):
                response = self.token.downloadRaw(token)
                return response
            time.sleep(1)

    # Print a scans summary
    def printScanSummary(self,scanID):
        scan = self.scan.details(scanID)
        print("Host\t\tVulns.")
        print("-------------------------------------")
        for host in scan["hosts"]:
            id = host["host_id"]
            hostDetails = self.scan.hostDetails(scanID, id)
            print(hostDetails["info"]["host-ip"] + "\t" + str(len(hostDetails["vulnerabilities"])))

    # Return string output of scan details optimized for splunk
    def outputForSplunk(self,scanID):
        details = self.scan.details(scanID)
        scanName = details["info"]["name"]
        scanTime = datetime.datetime.fromtimestamp(details["info"]["scan_end"]).strftime('%Y-%m-%d %H:%M:%S')
        results = {}
        for host in details["hosts"]:
            hostDetails = self.scan.hostDetails(scanID,host["host_id"])
            for vuln in hostDetails["vulnerabilities"]:
                if vuln["severity"]>2:
                    try:
                        results[vuln["plugin_name"]]["hosts"].append(host["hostname"])
                    except:
                        results[vuln["plugin_name"]] = {"hosts":[host["hostname"]],"severity":vuln["severity"],"scanName":scanName,"scanTime":scanTime}

        return (json.dumps(results)+"\n","")[len(results)<1]

class Nesrest:
    # Initialize the nesrest class
    def __init__(self, akey, skey, url):
        self.akey = akey
        self.skey = skey
        self.baseURL = url
        self.header = {"X-ApiKeys" : "accessKey=" + self.akey + ";secretKey=" + self.skey +";"}

    ###
    # Nesrest Functions
    # These functions are focused on HTTP requests and used by the API classes
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

    # Put request
    def putRequest(self,endpoint,data):
        req = requests.put(self.baseURL+"/"+endpoint, headers=self.header, data=data, verify=False)
        res = req.status_code
        return res

    # To download a file
    def downloadFile(self,endpoint,token):
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

###
# API Classes
# These classes serve to interface directly with the API
###

class Folder(Nesrest):
    # Return a list of folders
    def list(self):
        response = self.getRequest("folders/",0)
        return response["folders"]

class Scanner(Nesrest):
    # Return a list of scans
    def list(self,folderID=None):
        if folderID is None:
            response = self.getRequest("scans",0)
            return response["scans"]
        else:
            response = self.getRequest("scans",{"folder_id":folderID})
            return response["scans"]

    # Return a list of scans from a folder given folderID
    def details(self,scanID):
        response = self.getRequest("scans/"+str(scanID),0)
        return response

    # Return a list of scans from a folder given folderID
    def hostDetails(self,scanID,hostID):
        response = self.getRequest("scans/"+str(scanID)+"/hosts/"+str(hostID),0)
        return response

    # Return Plugin details per scan
    def pluginDetails(self,scanID,hostID,pluginID):
        response = self.getRequest("scans/"+str(scanID)+"/hosts/"+str(hostID)+"/plugins/"+str(pluginID),0)
        return response

    # Request a scan export
    def exportRequest(self,scanID):
        response = self.postRequest("scans/"+str(scanID)+"/export",{"format":"csv"})
        return response["token"]

class Token(Nesrest):
    # Return the status of a given token
    def status(self,token):
        response = self.getRequest("tokens/"+str(token)+"/status/",0)
        return response["message"]

    # Return the file from a given token
    def download(self,token):
        response = self.downloadFile("tokens/"+str(token)+"/download/",str(token))
        return response

    # Return the file from a given token
    def downloadRaw(self,token):
        response = self.getRequest("tokens/"+str(token)+"/download/",1)
        return response

class Policy(Nesrest):
    # Return a list of policies
    def list(self):
        response = self.getRequest("policies/",0)
        return response["policies"]

    # Get policy details
    def details(self,policyID):
        response = self.getRequest("policies/"+str(policyID),0)
        return response

    # Configure a policy
    def configure(self,policyID,data):
        response = self.putRequest("policies/"+str(policyID),data)
        return response

    # Create a policy
    def create(self,data):
        response = self.postRequest("policies/",data)
        return response

class Plugin(Nesrest):
    # Return a list of plugin Families or plugins
    def list(self,familyID=None):
        if familyID is None:
            response = self.getRequest("plugins/families",0)
            return response["families"]
        else:
            response = self.getRequest("plugins/families/"+str(familyID),0)
            return response

    # Get plugin details
    def details(self,pluginID):
        response = self.getRequest("plugins/plugin/"+str(pluginID),0)
        return response
