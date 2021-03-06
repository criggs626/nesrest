from nesrest import Nessus
import json

def loadConfig(folders, nessus):
    try:
        # If config exists load it
        configFile = open("config.json","r")
        config = json.loads(configFile.read())
        configFile.close()
        return config
    except:
        # Generate Config file
        config = {}
        config["folders"] = folders
        config["scans"] = []
        for folderID in folders:
            scans = nessus.scan.list(folderID)
            for scan in scans:
                temp = {}
                temp["id"] = scan["id"]
                temp["name"] = scan["name"]
                temp["lastModified"] = scan["last_modification_date"]
                config["scans"].append(temp)
        # Write results
        configFile = open("config.json","w")
        configFile.write(json.dumps(config))
        configFile.close()
        splunkFolderSave(folders, nessus)
        return config

def updateConfig(config):
    # Write results
    configFile = open("config.json","w")
    configFile.write(json.dumps(config))
    configFile.close()

def splunkFolderSave(folders, nessus, config=None):
    outfile = open("nessusScans.json","a")
    if config is None:
        for folder in folders:
            scans = nessus.scan.list(folder)
            for scan in scans:
                outfile.write(nessus.outputForSplunk(scan["id"]))
    else:
        for folder in folders:
            scans = nessus.scan.list(folder)
            for scan in scans:
                for oldScan in config["scans"]:
                    if oldScan["id"] == scan["id"] and scan["status"] != "running":
                        if scan["last_modification_date"] > oldScan["lastModified"]:
                            outfile.write(nessus.outputForSplunk(scan["id"]))
                            oldScan["lastModified"] = scan["last_modification_date"]
                        else:
                            break
                    else:
                        pass

    outfile.close()
    return config


def main():
    # API Keys
    accessKey = ""
    secretKey = ""
    baseURL = ""
    folders = []

    # Create Nessus Object
    nessus = Nessus(accessKey, secretKey, baseURL)


    # Load config
    config = loadConfig(folders, nessus)
    config = splunkFolderSave(folders, nessus, config)
    updateConfig(config)


main()
