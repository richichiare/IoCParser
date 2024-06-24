import json
import urllib.request
import urllib.error
import csv

def main():

    ioc_url = input("IoC URL: ")
    try:
        req = urllib.request.Request(ioc_url)
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        ioc_list_json = data[list(data.keys())[0]]["ioc_list"]
        print(ioc_list_json)

        #write md5
        md5_ioc = ioc_list_json["md5"]
        for item in md5_ioc:
            print(item)

        #write sha1
        sha1_ioc = ioc_list_json["sha1"]

        #write sha256
        sha256_ioc = ioc_list_json["sha256"]


        #write domain
        domain_ioc = ioc_list_json["domain"]

        #write url
        url_ioc = ioc_list_json["url"]

        #write IPv4
        ipv4_ioc = ioc_list_json["ipv4"]


    except urllib.error.HTTPError as err:
        print(err)

    return

main()