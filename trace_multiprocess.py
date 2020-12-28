import sys


from scapy.layers.inet import IP, ICMP, UDP, traceroute
from scapy.layers.inet6 import traceroute6
from tqdm import tqdm, trange
import time
import datetime
import struct
import random
import sys
import re
import optparse
import threading
import os
import multiprocessing
import fcntl


def run(ips, hops, begin, end, cnt, output_file, total, initial_time, fast):
    result = []
    # each process writes to the file after finishing every <write_interval> ip addresses.
    write_interval = 500
    for i in range(begin, end):
        # print('Working on %d, begin = %d, end = %d' % (i, begin, end))
        start_time = time.time()
        ip = ips[i].strip()
        result.append('# ' + ip + '\t')

        # # using nmap to do traceroute
        # shell_output = os.popen('sudo nmap -sn --traceroute -6 ' + ip)
        # for line in shell_output.readlines():
        #     if line[0].isdecimal():
        #         split_list = line.split()
        #         if len(split_list) == 5:
        #             result.append(split_list[3] + split_list[4] +'\t')
        #         elif len(split_list) == 4:
        #             result.append(split_list[3] + '\t')


        # # using scamper to do traceroute
        # shell_output = os.popen('''sudo scamper -I "trace -m %d -w 2 %s" ''' % (hops, ip))
        # for line in shell_output.readlines():
        #     if len(line.split()) == 4:
        #             result.append(line.split()[1] + '\t')


        # using scapy to do traceroute
        # Try several times to traceroute with value of timeout increasing progressively.
        timeout = 3
        times = 0
        ok = False
        

        if fast: # keep timeout = 2, only try once for each address.
            res, _ = traceroute6(ip, maxttl=hops, verbose=False)
            hasTarget = False
            for _, rcv in res:
                if rcv.src != ip:
                    result.append(rcv.src + '\t')  
                else:
                    hasTarget = True
            if hasTarget:
                result.append('$')

        else:
            while not ok:
                times += 1
                res, _ = traceroute6(ip, maxttl=hops, verbose=False, timeout=timeout)
                try:
                    for _, rcv in sorted(list(res.get_trace().values())[0].items(), key=lambda item:item[0]):
                        if rcv[1]:
                            # result.append(rcv[0] + '$')
                            result.append('$')
                            ok = True
                            break
                        else:
                            result.append(rcv[0] + '\t')    
                except:
                    pass 
                timeout += 1
                if not ok and times >= 4:
                    result.append('?')
                    break

        

        result.append('\n')
        current_time = time.time()
        cnt_backup = 0
        with cnt.get_lock():
            cnt.value = cnt.value + 1
            cnt_backup = cnt.value
        percent = round(cnt_backup * 1000 / total)
        info = '|'
        info += '*' * (percent // 10)
        info += '-' * (100 - percent // 10)
        info += '|'
        info += ' [%.1f%%](%d/%d)' % (percent / 10, cnt_backup, total)
        info += ' Current:%.2f addr/sec' % (1 / (current_time - start_time))
        info += ' Average:%.2f addr/sec' % (cnt_backup / (current_time - initial_time))
        if not fast:
            info += ' ' + str(times) + ' tries'
        print('\r' + info, end='')


        if (i + 1 - begin) % write_interval == 0:
            with open(output_file, 'a+', encoding='utf-8') as output:
                fcntl.flock(output.fileno(), fcntl.LOCK_EX)
                for j in result:
                    output.write(j)
                fcntl.flock(output.fileno(), fcntl.LOCK_UN)
            result.clear()

    with open(output_file, 'a+', encoding='utf-8') as output:
        fcntl.flock(output.fileno(), fcntl.LOCK_EX)
        for i in result:
            output.write(i)
        fcntl.flock(output.fileno(), fcntl.LOCK_UN)


if __name__ == '__main__':
    # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    parser = optparse.OptionParser(
        '用法：\n sudo python3 trace_multiprocess.py --hops 跳数 --process 进程数 --fast')
    parser.add_option('--hops', '-H', dest='hops', type='string',
                      default='30', help='跳数')
    parser.add_option('--process', '-p', dest='pcs', type='string', help='进程数')
    parser.add_option('--fast', '-f', action='store_true', dest='fast')

    (options, args) = parser.parse_args()
    hops = int(options.hops)
    PROCESS_NUMBER = int(options.pcs)
    fast = options.fast

    dataFolder = './dataByNumber/'
    # dataFolder = './dataForTest/'
    resultFolder = './dataResult/'
    for csv_name in os.listdir(dataFolder):
        file_name = dataFolder + str(csv_name)
        f = open(file_name, 'r')
        output_file = resultFolder + \
            str(csv_name).split('_')[-1][:-4] + '.txt'

        ips = f.readlines()

        f.close()

        n = len(ips)
        cnt = multiprocessing.Value("i", 0)

        p_list = []

        initial_time = time.time()
        print('\nStarted Working on %s at %s' %
              (csv_name, time.strftime("%Y-%m-%d %H:%M:%S.",
                                       time.localtime(initial_time + 3600 * 8))))
        # Time Zone of Beijing: GMT +8

        


        for i in range(PROCESS_NUMBER - 1):

            p = multiprocessing.Process(target=run,
                                        args=(ips,
                                              hops,
                                              i * (n // (PROCESS_NUMBER - 1)),
                                              (i + 1) *
                                              (n // (PROCESS_NUMBER - 1)),
                                              cnt,
                                              output_file,
                                              n,
                                              initial_time,
                                              fast
                                              ))
            p.start()
            p_list.append(p)

        p = multiprocessing.Process(target=run,
                                    args=(ips,
                                          hops,
                                          n // (PROCESS_NUMBER - 1) *
                                          (PROCESS_NUMBER - 1),
                                          n,
                                          cnt,
                                          output_file,
                                          n,
                                          initial_time,
                                          fast
                                          ))
        p.start()
        p_list.append(p)

        for p in p_list:
            p.join()

        finish_time = time.time()
        time.sleep(1)


        print('\nFinished Working on %s at %s' %
              (csv_name, time.strftime("%Y-%m-%d %H:%M:%S.",
                                       time.localtime(finish_time + 3600 * 8))),
              end='  ')
        print('Time Cost: %s.' % datetime.timedelta(
            seconds=finish_time - initial_time))
