#status code 
#200 request success
#403 Forbidden (CSRF token not set) 
#500 internal server error
import requests

class RabbitClient:
    def __init__(self):
        self.downloadURL=""
        self.uploadURL=""
        self.client=None
        self.csrftoken=""
    
    def startSession(self):
        self.uploadURL='http://127.0.0.1:8000/uploadxml/'
        self.client = requests.session()
        r = self.client.get(self.uploadURL)
        self.csrftoken=self.client.cookies['csrftoken']

        #print(r.status_code)
        #print(self.csrftoken)

    def clientUploadfile(self,filetoupload):
        with open(filetoupload,'rb') as xmlfile:
            r = self.client.post(
                self.uploadURL,
                files={'docfile':xmlfile},
                data={'csrfmiddlewaretoken':self.csrftoken}
                )
            #print(r2.status_code)
            #print(r2.content)
    
    def clientDownloadfile(self):
        self.downloadURL='http://127.0.0.1:8000/downloadpy/core_function'
        r = self.client.get(self.downloadURL)
        pyfile = open("rabbit_scanner.py",'wb+')
        pyfile.write(r.content)
        pyfile.close()

        #print("clientDownloadfile")
        #print(r.status_code)

if __name__ == '__main__':
     rab=RabbitClient()
     rab.startSession()
     rab.clientUploadfile('test.txt')
     rab.clientDownloadfile()