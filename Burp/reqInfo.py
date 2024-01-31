from burp import IBurpExtender
from burp import IProxyListener
from burp import IInterceptedProxyMessage


class BurpExtender(IBurpExtender, IProxyListener):

   
    def registerExtenderCallbacks(self, callbacks):
      
        self._callbacks = callbacks

       
        callbacks.setExtensionName("Request Info")

        
        callbacks.registerProxyListener(self)

   
    def processProxyMessage(self, messageIsRequest, message):
        
        if messageIsRequest:
           
            host = message.getMessageInfo().getHttpService().getHost()
            port = message.getMessageInfo().getHttpService().getPort()
            url = self._callbacks.helpers.analyzeRequest(message.getMessageInfo()).getUrl().toString()

            
            print("Intercepted request to: {}:{} {}".format(host, port, url))

        #no change/modification is introduced in the request or response     
        message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)

#Creating an instance of the BurpExtender class
burp_extender = BurpExtender()
