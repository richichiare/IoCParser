import helper
import json
import urllib.request
import urllib.error
import csv

def open_csv(path):
    file = open(path, mode="w")
    ioc_writer = csv.DictWriter(file, fieldnames=helper.csv_header)
    ioc_writer.writeheader()
    return (ioc_writer, file)


def main():

    ioc_url = input("IoC URL: ")
    csv_path = input("Output file: ")
    try:
        req = urllib.request.Request(ioc_url)
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())

        # Extract name of the campaign
        campaign_title = data[list(data.keys())[0]]["name"]
        # Extract json node containing iocs
        campaign_description = data[list(data.keys())[0]]["description"]
        campaign_iocs = data[list(data.keys())[0]]["ioc_list"]

        (ioc_writer, file) = open_csv(csv_path)

        #write md5
        md5_ioc = campaign_iocs["md5"]
        for item in md5_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.MD5, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK_AND_REMEDIATE, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        #write sha1
        sha1_ioc = campaign_iocs["sha1"]
        for item in sha1_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.SHA1, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK_AND_REMEDIATE, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        #write sha256
        sha256_ioc = campaign_iocs["sha256"]
        for item in sha256_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.SHA256, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK_AND_REMEDIATE, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        #write domain
        domain_ioc = campaign_iocs["domain"]
        for item in domain_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.DOMAIN, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        #write url
        url_ioc = campaign_iocs["url"]
        for item in url_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.URL, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        #write IPv4
        ipv4_ioc = campaign_iocs["ipv4"]
        for item in ipv4_ioc:
            ioc_writer.writerow({helper.INDICATOR_TYPE:helper.IPADDR, helper.INDICATOR_VALUE:item,
                                 helper.ACTION:helper.BLOCK_AND_REMEDIATE, helper.SEVERITY:helper.HIGH,
                                 helper.TITLE:campaign_title, helper.DESCRIPTION:campaign_description,
                                 helper.CATEGORY:"Malware", helper.GEN_ALERT:"True"})

        file.flush()
        file.close()

    except urllib.error.HTTPError as err:
        print(err)

    return

main()