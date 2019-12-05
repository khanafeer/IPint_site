from TwitterSearch import *
import os
import requests
import json
import socket
from OTXv2 import OTXv2
import IndicatorTypes
import itertools

class Scan:
    def __init__(self, IP='', Domain='',Hash=''):
        self.results = {}

        self.IPaddr = IP
        self.Domain = Domain
        self.Hash = Hash

        self.config_file_check()

        self.targetPortscan = [80, 443, 8000, 20, 21, 22, 23, 25, 53]
        self.headers = {'user-agent': 'Mozilla/5.0 (Check.py extended address information lookup tool)',
                        'referer': 'https://www.github.com/AnttiKurittu/check'}

        self.vtk_couter = 0
        self.IPIs = self.settings['VirusTotalAPIKey'].split(',')

    def config_file_check(self):
        self.settings = {}
        with open(os.path.join(os.getcwd(),"api_config"), "r+") as f:
            for line in f:
                if line[0] == "#":
                    continue
                if ":" in line:
                    (key, val) = line.split(":")
                    self.settings[key.strip()] = val.strip()
            f.close()


    def scan_all(self):
        self.whois()
        self.virus_total()
        self.otx_scan()
        self.abuse_ip_db()
        self.twitter_scan()
        self.meta_scan()
        self.scan_ports()
        self.hony_db()
        return self.results

    # def hybrid_analysis(self):
    #     headers = {'api-key':'670q8o4mcaed70a6nwmn5hmae741ed915y6sbo0i11adf72556fun2yj5a130f75'}
    #     r = requests.post('https://www.hybrid-analysis.com/api/v2/search/hash',headers=headers,data={'hash':'ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA'})
    #     print(r.text)
    # def scan_any_run(self):
    #     data = {"msg":"sub","id":"hRmWEoaRM8sZSZ7MS","name":"publicTasks","params":[50,0,{"isPublic":true,"hash":"665bad57884a0e761c3eb923fcfe6f001347c131593af1af46baff5b24ec3171","major":"","bit":"","runtype":[],"name":"","verdict":[],"ext":[],"tag":"","significant":false,"ip":"","fileHash":"","mitreId":"","sid":0,"skip":0}]}
    #     req = requests.post('')

    def twitter_scan(self):
            try:
                tso = TwitterSearchOrder()  # create a TwitterSearchOrder object
                keyword_domain = "\"" + self.Domain + "\""
                keyword_ip = "\"" + self.IPaddr + "\""
                if self.IPaddr != "":
                    tso.set_keywords([keyword_ip], or_operator=True)
                    keywords_desc = "IP address"
                elif self.Domain != "":
                    tso.set_keywords([keyword_domain], or_operator=True)
                    keywords_desc = "domain name"
                else:
                    self.results['twitter'] = {}
                    return 0

                # tso.set_language('en')
                tso.set_include_entities(False)
                tso.remove_all_filters()
                ts = TwitterSearch(
                    consumer_key=self.settings['TwitterConsumerKey'],
                    consumer_secret=self.settings['TwitterConsumerSecret'],
                    access_token=self.settings['TwitterAccessToken'],
                    access_token_secret=self.settings['TwitterAccessTokenSecret']
                )
                twts = []
                for tweet in ts.search_tweets_iterable(tso):
                    twts.append(dict(itertools.islice(tweet.items(), 4)))
                self.results['twitter'] = twts
            except Exception as ex:
                print('tw',ex)
                self.results['twitter'] = {}

    def otx_scan(self):
        try:
            otx = OTXv2('b2ffda0576d05368171a92f08dc2c747f7dc0671b18a97f09e6c916fa5d618ca')
            if self.IPaddr != '':
                out = otx.get_indicator_details_full(IndicatorTypes.IPv4, self.IPaddr)
            elif self.Domain  != '':
                out = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, self.IPaddr)
            else:
                out = {}
            self.results['otx'] = out
        except Exception as ex:
            print('otx',ex)
            self.results['results'] = {}

    def abuse_ip_db(self):
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            if self.IPaddr != '' :
                querystring = {
                    'ipAddress': '{}'.format(self.IPaddr),
                    'maxAgeInDays': '90'
                }
            else:
                self.results['abuse_ip_db'] = {}
                return 0

            headers = {
                'Accept': 'application/json',
                'Key': '{}'.format(self.settings['abuse_ip_db'])
            }

            response = requests.request(method='GET', url=url, headers=headers, params=querystring)

            # Formatted output
            self.results['abuse_ip_db'] = response.json()

        except Exception as ex:
            print('api',ex)
            self.results['abuse_ip_db'] = {}

    def hony_db(self):
        try:
            url = ''

            headers = {
                'X-HoneyDb-ApiId': "{}".format(self.settings['hony_db_id']),
                'X-HoneyDb-ApiKey': "{}".format(self.settings['hony_db_key'])
            }
            response = requests.request("GET", url, headers=headers)

            self.results['hony_db'] = response.json()
        except Exception as ex:
            print('hony_db', ex)
            self.results['hony_db'] = {}

    def meta_scan(self):
        try:
            if self.IPaddr:
                url = "https://api.metadefender.com/v4/ip/{}".format(self.IPaddr)
            elif self.Domain:
                url = "https://api.metadefender.com/v4/domain/{}".format(self.Domain)
            else:
                url = "https://api.metadefender.com/v4/hash/{}".format(self.Hash)

            headers = {
                'apikey': "{}".format(self.settings['meta_scan'])
            }
            response = requests.request("GET", url, headers=headers)

            self.results['meta_scan'] = response.json()
        except Exception as ex:
            print('exx',ex)
            self.results['meta_scan'] = {}


    def virus_total(self):
            try:
                api_key = self.IPIs[self.vtk_couter]
                if self.IPaddr != "":
                    parameters_ip = {
                        'ip': self.IPaddr,
                        'apikey': api_key
                    }
                    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
                    params=parameters_ip
                else:
                    parameters_domain = {
                        'domain': self.Domain,
                        'apikey': api_key
                    }
                    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
                    params=parameters_domain
                vtresponse_dict = requests.get(url,params).json()
                if vtresponse_dict['response_code'] == 0:
                    self.results['virus_total'] = {}
                else:
                    self.results['virus_total'] = vtresponse_dict

            except IndexError:
                self.vtk_couter = 0
                self.virus_total()
            except Exception as ex:
                print(ex)
                if 'No JSON object could be decoded' in ex or 'Max retries exceeded with url' in ex:
                    self.vtk_couter += 1
                    self.virus_total()
                return 0

    def whois(self):
        try:
            if self.IPaddr != '':
                g = requests.get('https://ipinfo.io/{}/json?token={}'.format(self.IPaddr,self.settings['whois_token']))
            elif self.Domain != '':
                g = requests.get('https://ipinfo.io/{}/json?token={}'.format(self.Domain,self.settings['whois_token']))
            else:
                return 0
            self.results['whois'] = g.json()

        except Exception as ex:
            print(ex)
            self.results['whois'] = {}

    def scan_ports(self):
        socket.setdefaulttimeout(3)
        openports = []
        try:
            for port in self.targetPortscan:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((self.IPaddr, port))
                if result == 0:
                    openports.append(port)
                sock.close()
            self.results['ports'] = openports
        except Exception as ex:
            print(ex)
            self.results['ports'] = []