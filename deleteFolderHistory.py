from nesrest import Nessus

#Return the scan IDs from a provided folderID
def getScanIDs(nessus,folderID):
    ids = []
    scans = nessus.scan.list(folderID)
    for scan in scans:
        ids.append(scan["id"])

    return ids

#Delete the history from all scanIDs, but retain a minimum set by retention
def getHistory(nessus,id):
    details = nessus.scan.details(id)
    return details["history"]

def deleteScanHistory(nessus,scanID,histories,retain):
    if not histories:
        return 0
    elif len(histories) - 1 == retain:
        history = histories.pop(0)
        print("deleting " + str(history["history_id"]) + " from " + str(scanID))
        nessus.scan.deleteHistory(scanID,history["history_id"])
        return 0
    elif len(histories) > retain:
        history = histories.pop(0)
        print("deleting " + str(history["history_id"]) + " from " + str(scanID))
        nessus.scan.deleteHistory(scanID,history["history_id"])
        deleteScanHistory(nessus,scanID,histories,retain)
    elif len(histories) == retain:
        return 0


def main():
    # API Keys and required variables
    accessKey = ""
    secretKey = ""
    baseURL = ""
    folder = 0
    retain = 0

    # Create Nessus Object
    nessus = Nessus(accessKey, secretKey, baseURL)

    #Get the scanIDs to deleteHistory
    scans = getScanIDs(nessus,folder)

    #For each scanID delete the history
    for id in scans:
        histories = getHistory(nessus,id)
        deleteScanHistory(nessus,id,histories,retain)

main()
