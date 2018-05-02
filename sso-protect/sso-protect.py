import time
import re
import threading
import subprocess
import configparser


def follow(the_file):
    the_file.seek(0, 2)
    while True:
        file_line = the_file.readline()
        if not file_line:
            time.sleep(0.001)
            continue
        yield file_line


def clear_map(seconds):
    while True:
        ip_map.clear()
        time.sleep(int(seconds))


def do_fail_ban(need_ban_ip):
    deny_file = open('E:\\nginx-1.14.0\\conf\\deny.conf', 'a')
    deny_file.write('deny %s;' % need_ban_ip)
    deny_file.close()
    subprocess.call('nginx -s reload')


def write_to_html(need_ban_ip, service_path):
    report_html = open('403.html', 'a')
    time_tuple = time.localtime()
    report_html.write('<p>%s-%s-%s %s:%s:%s ----- ip:%s  service-path:%s<p>\n' %
                      (time_tuple[0], time_tuple[1], time_tuple[2], time_tuple[3], time_tuple[4], time_tuple[5],
                       need_ban_ip, service_path))
    report_html.close()


cp = configparser.ConfigParser()
cp.read('sso-protect-config.conf')
limit_time = cp.get('config', 'limit_time')
limit_count = cp.get('config', 'limit_count')
limit_service = cp.get('config', 'limit_service')
limit_source = cp.get('config', 'limit_source')

ip_map = {}

thread = threading.Thread(target=clear_map, args=limit_time)
thread.start()

log_file = open(limit_source, "r")
log_lines = follow(log_file)
ip_regex = re.compile('\d+\.\d+\.\d+\.\d+')
for line in log_lines:
    if limit_service in line:
        ip = ip_regex.search(line).group()
        if ip in ip_map:
            ip_map[ip] += 1
            if ip_map[ip] > int(limit_count):
                do_fail_ban(ip)
                write_to_html(ip, limit_service)
        else:
            ip_map[ip] = 1
