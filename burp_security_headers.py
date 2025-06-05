
from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Security Headers Checker")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        analyzed_response = self._helpers.analyzeResponse(response)
        headers = analyzed_response.getHeaders()
        issues = []

        missing_headers = []
        required = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"
        ]

        for header in required:
            if not any(h.lower().startswith(header.lower()) for h in headers):
                missing_headers.append(header)

        if missing_headers:
            issues.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Missing Security Headers",
                "The following headers are missing: " + ", ".join(missing_headers),
                "Information"
            ))

        return issues if issues else None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Certain"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._httpMessages
    def getHttpService(self): return self._httpService