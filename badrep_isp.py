'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
# NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
# DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
# WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Tip jars!
# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# Created by https://github.com/tg12
import requests
import re
from fake_useragent import UserAgent
from cymruwhois import Client
import pandas as pd

c = Client()
ua = UserAgent()
headers = {
    'User-Agent': ua.random,
}

ips_to_check = []
ip_data = []
owner_lst = []

lists_to_agg = [
    "https://talos-intelligence-site.s3.amazonaws.com/production/document_files/files/000/091/590/original/ip_filter.blf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20200503%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200503T173407Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=10feb0d139742092e98186a296d30ada45ee9081777ab8197d0c5daf0308384b",
    "http://talosintel.com/feeds/ip-filter.blf",
    "https://reputation.alienvault.com/reputation.generic",
    "https://www.matthewroberts.io/api/threatlist/latest",
    "https://threatintel.stdominics.sa.edu.au/",
    "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt",
    "https://github.com/stamparm/ipsum/blob/master/ipsum.txt?raw=true",
    "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
    "https://raw.githubusercontent.com/tg12/bad_packets_blocklist/master/bad_packets_list.txt"]


for item in lists_to_agg:
    try:
        r = requests.get(item, timeout=10, headers=headers)
        for each in list(re.findall(r'[0-9]+(?:\.[0-9]+){3}', r.text)):
            if each not in ips_to_check:
                ips_to_check.append(each)
                print("[+]debug, adding ..." + str(each))
    except BaseException:
        pass

ips_to_check.sort()
# print (ips_to_check)

for each in ips_to_check:
    try:
        tmp_lst = []
        tmp_lst.append(each)
        r = c.lookup(each)
        print("[+]debug, adding ..." + str(r.owner))
        tmp_lst.append(str(r.owner))
        owner_lst.append(str(r.owner))
        ip_data.append(tmp_lst)
    except BaseException:
        pass

ip_data.sort(key=lambda x: x[1])
# print(tabulate(ip_data))
f = open("owner_data.txt", "w")
f.write(str(ip_data))
f.close()

owner_count = pd.Series(owner_lst).value_counts().to_string()
# print(owner_count)

f = open("bad_isp_report.txt", "w")
f.write(str(owner_count))
f.close()
