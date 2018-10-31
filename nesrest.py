import requests
import json
import time
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
    def downloadScan(self,scanID,time):
        token = self.exportRequest(scanID)
        for i in range(0,time):
            response = self.getTokenStatus(token)
            if(response == "The download is ready."):
                response = self.getTokenDownload(token)
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

    ###
    # API Functions
    # These functions interact with the API and return the logical results
    ###
    # Return a list of folders
    def getFolders(self):
        response = self.getRequest("folders")
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
        else:
            req = requests.get(self.baseURL+"/"+endpoint, headers=self.header, verify=False)
            res = json.loads(req.text)
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
