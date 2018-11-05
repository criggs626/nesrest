import tkinter as tk
from tkinter import font
from tkinter import messagebox
from tkinter import filedialog
from nesrest import Nesrest

class Application(tk.Frame):
    def __init__(self, nessus, master=None):
        super().__init__(master)
        self.nessus = nessus
        self.master = master
        self.grid()
        self.fillFolders()

    def fillFolders(self):
        lable = tk.Label(self.master, text="Folders:")
        lable.grid(row=0,column=0)
        folders = self.nessus.getFolders()
        lb = tk.Listbox(self.master,font=font.Font(size=16),height=20)
        lb.grid(row=1,column=0,padx=2)
        lb.bind('<<ListboxSelect>>', self.folderClick)
        self.folders = folders
        self.folderList = lb
        for folder in folders:
            if(folder["name"] != "Trash"):
                lb.insert("end",folder["name"])

    def fillScans(self,id):
        lable = tk.Label(self.master, text="Scans:")
        lable.grid(row=0,column=1)
        scans = self.nessus.getScansFromFolder(id)
        lb = tk.Listbox(self.master,font=font.Font(size=16),height=20)
        lb.grid(row=1,column=1,padx=2)
        self.scans = scans
        self.scanList = lb
        lb.bind('<<ListboxSelect>>', self.scanClick)
        for scan in scans:
            lb.insert("end",scan["name"])

    def downloadButton(self,scanName):
        lable = tk.Label(self.master, text="\t\t")
        lable.grid(row=0,column=3)
        lable = tk.Label(self.master, text=scanName)
        lable.grid(row=0,column=3)
        b = tk.Button(self.master, text="Download Scan",height=3,width=20,command=lambda: self.download(scanName))
        b.grid(row=1,column=3)

    def folderClick(self,data):
        for folder in self.folders:
            if(self.folderList.get(self.folderList.curselection()) == folder["name"]):
                self.fillScans(folder["id"])
                return None

    def scanClick(self,data):
        for scan in self.scans:
            if(self.scanList.get(self.scanList.curselection()) == scan["name"]):
                self.downloadButton(scan["name"])
                return None

    def download(self,name):
        for scan in self.scans:
            if(name == scan["name"]):
                messagebox.showinfo("Status", "The download has begun. Please wait until a confirmation has been given to click anything else")
                response = self.nessus.downloadRaw(scan["id"],60)
                file =  filedialog.asksaveasfile(initialdir = "./",title = "Save file",mode='w', defaultextension=".csv")
                file.write(response)
                file.close()
                return None

def main():
    accessKey = ""
    secretKey = ""
    baseURL = ""
    nessusAPI = Nesrest(accessKey, secretKey, baseURL)

    root = tk.Tk()
    root.title("iQor Nessus Scans")
    root.geometry("650x430")
    app = Application(nessusAPI,master=root)
    app.mainloop()

main()
