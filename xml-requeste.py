from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XML-RPC Requester")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        url = self._helpers.analyzeRequest(messageInfo).getUrl()
        if "xmlrpc.php" in url.getPath():
            if messageIsRequest:
                # Get the headers from the request
                headers = messageInfo.getRequest()

                # Extract the URL from the headers
                url = self.extractURL(headers)
                # Modify the request if necessary, or construct a new one
                new_request = self.buildNewRequest(url)

                # Send the new request
                new_request_bytes = self._helpers.stringToBytes(new_request)
                messageInfo.setRequest(new_request_bytes)

            else:
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)
                # Print the response
                print("Response for URL: " + messageInfo.getUrl().toString())
                print(self._helpers.bytesToString(response))
                newResp=self._helpers.bytesToString(response)
                if "Hello" in newResp:
                    self._callbacks.addScanIssue(
                        # Define the issue details
                        CustomScanIssue(
                            messageInfo.getHttpService(),
                            messageInfo.getUrl(),
                            "XML-RPC Requester vuln Detected",
                            "XML-RPC Requester vuln Detected for more info visit the following page https://www.iprog.it/blog/sicurezza-informatica/attack-wordpress-abusing-xmlrpc/",
                            "High",  # Set the severity level as needed
                            "Certain"  # Set the confidence level as needed
                        )
                    )
                else:
                    print("No vuln")

    def extractURL(self, headers):
        # Convert headers to string
        headers_str = self._helpers.bytesToString(headers)

        # Split the headers by newline
        header_lines = headers_str.split("\n")

        # Extract the Host header to get the URL
        for line in header_lines:
            if line.startswith("Host:"):
                host = line.split(" ")[1].strip()
                return "http://" + host

        return None

    def buildNewRequest(self, url):
        if url is None:
            return None
        xml_payload = '''<?xml version="1.0" encoding="utf-8"?><methodCall><methodName>demo.sayHello</methodName> <params></params></methodCall>'''
        # Construct the request with the XML-RPC payload and custom header
        new_request = "POST /xmlrpc.php HTTP/1.1\r\n"
        new_request += "Host: {}\r\n".format(url.split("://")[1])
        new_request += "Content-Type: text/xml\r\n"
        new_request += "Content-Length: {}\r\n".format(len(xml_payload))
        new_request += "\r\n"
        new_request += xml_payload

        return new_request

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getHost(self):
        return self._httpService.getHost()

    def getPort(self):
        return self._httpService.getPort()

    def getProtocol(self):
        return self._httpService.getProtocol()

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return "Custom Issue Type"

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return "Background information about the issue."

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return None

    def getHttpService(self):
        return self._httpService


# Required boilerplate to make the extension load
callbacks = None

# Start the extension
extender = BurpExtender()

