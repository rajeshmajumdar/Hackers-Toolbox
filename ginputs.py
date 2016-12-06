import urllib2
import os
import sys
import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

def Download(url):
    file_name = url.split('/')[-3]
    final_name = file_name+'.zip'
    with open(final_name, "wb") as f:
        print "\nDownloading %s" % file_name
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')

        if total_length is None: # no content length header
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('=' * done, ' ' * (50-done)) )    
                sys.stdout.flush()
