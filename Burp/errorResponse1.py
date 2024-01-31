# Import the required Burp classes
from burp import IBurpExtender
from burp import IProxyListener
from burp import IInterceptedProxyMessage


class BurpExtender(IBurpExtender, IProxyListener):

    
    def registerExtenderCallbacks(self, callbacks):
       
        self._callbacks = callbacks

        
        callbacks.setExtensionName("Error Responses")


        callbacks.registerProxyListener(self)

        
        self.file_path = "/Users/ashwiniraj/Desktop/res.txt"

   
    def processProxyMessage(self, messageIsRequest, message):
       
        if not messageIsRequest:
            try:
               
                response_info = self._callbacks.helpers.analyzeResponse(message.getMessageInfo().getResponse())

                
                status_code = response_info.getStatusCode()

               
                if 400 <= status_code <= 599:
                    
                    request_info = message.getMessageInfo()
                    host = request_info.getHttpService().getHost()
                    port = request_info.getHttpService().getPort()
                    url = self._callbacks.helpers.analyzeRequest(request_info).getUrl().toString()

                    
                    print("Error response intercepted from: {}:{} {}".format(host, port, url))

                    
                    with open(self.file_path, "a") as file:
                        file.write("Error response from: {}:{} {}\n".format(host, port, url))
                        file.write("Status Code: {}\n".format(status_code))
                        file.write("Response:\n{}\n\n".format(self._callbacks.helpers.bytesToString(message.getMessageInfo().getResponse())))
            except Exception as e:
                print("Error processing message: {}".format(e))

        #no change/modification is introduced in the response
        message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)

#Creating an instance of the BurpExtender class
burp_extender = BurpExtender()
