csv_header = ["IndicatorType","IndicatorValue","ExpirationTime","Action","Severity","Title","Description",
              "RecommendedActions","Scope/DeviceGroups","Category","MitreTechniques","GenerateAlert"]

MD5 = "FileMd5"
SHA1 = "FileSha1"
SHA256 = "FileSha256"
IPADDR = "IpAddress"
DOMAIN ="DomainName"
URL = "Url"

IndicatorType = ["FileMd5", "FileSha1", "FileSha256", "IpAddress", "Url", "DomainName"]
Category = ["SuspiciousActivity", "Malware"]
Severity = ["Low", "Medium", "High"]

# Header
INDICATOR_TYPE = "IndicatorType"
INDICATOR_VALUE ="IndicatorValue"
EXPIRATION_TIME = "ExpirationTime"
ACTION = "Action"
SEVERITY = "Severity"
TITLE = "Title"
DESCRIPTION = "Description"
RECOMMENDED_ACTIONS = "RecommendedActions"
SCOPE = "Scope/DeviceGroups"
CATEGORY = "Category"
MITRE = "MitreTechniques"
GEN_ALERT = "GenerateAlert"

# Action
BLOCK = "Block"
BLOCK_AND_REMEDIATE = "BlockAndRemediate"
HIGH = "High"
