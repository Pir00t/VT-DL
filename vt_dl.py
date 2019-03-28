import argparse
import json
import os
import requests
import subprocess
import sys
import tempfile

script_path = os.path.dirname(os.path.abspath(__file__))  # global script path

#

__author__ = 'Pir00t'
__date__ = 20190328
__version__ = 0.2
__description__ = 'Script to query VirusTotal API and open web directories. Then download the samples to a zip file.'

#

def vt_download(fhash):

    # read config file for creds
    with open('config.json', 'r') as f:
        config = json.load(f)

    # vars for download
    api_key = config['VirusTotal']['api_key']
    url = 'https://www.virustotal.com/vtapi/v2/file/download'
    params = {'apikey': api_key, 'hash': fhash}

    # create temp file in 'wb' mode
    temp = tempfile.NamedTemporaryFile(delete=True)

    # query the api
    try:
        print "Querying VirusTotal...\n"
        response = requests.get(url, params=params)
        response.raise_for_status()
        downloaded_file = response.content
        temp.write(downloaded_file)
        temp.flush()
        temp_path = temp.name
    except requests.exceptions.HTTPError as e:
        print e
        sys.exit(1)

    zipper(fhash, temp_path)
    temp.close()


def zipper(fhash, temp_path):

    # cmd to run local bash zip via subprocess
    zip_cmd = (['zip', '-ejPinfected', 'Samples/'+fhash+'.zip'] + [temp_path])
    zip_file = subprocess.Popen(zip_cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    zip_file.communicate()

    print "Done!\nFile saved to ./Samples"

    return

def main():

    print ("\nScript by %s" % __author__)
    print ("Current version %s\n" % __version__)

    # Add in argument options

    parser = argparse.ArgumentParser(description="Specify details to lookup")
    parser.add_argument("-d", "--download", help="Type md5/sha1/sha256 to download from VirusTotal")

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    else:
        args = parser.parse_args()

    if args.download:
        fhash = args.download
        vt_download(fhash)

#

if __name__ == '__main__':

    main()
