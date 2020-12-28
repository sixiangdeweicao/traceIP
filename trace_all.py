import sys


from scapy.layers.inet import IP, ICMP, UDP, traceroute
from scapy.layers.inet6 import traceroute6
from tqdm import tqdm
import time
import datetime
import struct
import random
import sys
import re
import optparse
import threading
import os


class TraceThread(threading.Thread):
    def __init__(self, begin, end):
        threading.Thread.__init__(self)
        self.begin = begin
        self.end = end

    # @profile
    def run(self):
        global hops
        global cnt
        global tbar
        global ips
        global output
        global mutex
        result = []
        # write to the file after finishing every 500 ip addresses.
        write_interval = 500
        for i in range(self.begin, self.end):
            ip = ips[i].strip()
            result.append(ip)
            res, _ = traceroute6(ip, maxttl=hops, verbose=False)
            for _, rcv in res:
                if rcv.src != ip:
                    result.append(rcv.src + '\t')
            result.append('\n')
            cnt += 1
            tbar.update(1)
            if (i + 1 - self.begin) % write_interval == 0:
                with mutex:
                    for j in result:
                        print(j, file=output, end='')
                result.clear()
        with mutex:
            for i in result:
                print(i, file=output, end='')


if __name__ == '__main__':
    # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    parser = optparse.OptionParser(
        '用法：\n sudo python3 trace_all.py --hops 跳数 --thread 线程数')
    parser.add_option('--hops', dest='hops', type='string',
                      default='30', help='跳数')
    parser.add_option('--thread', '-t', dest='thrd', type='string', help='线程数')

    (options, args) = parser.parse_args()
    hops = int(options.hops)
    THREAD_NUMBER = int(options.thrd)

    for csv_name in os.listdir('./dataByNumber'):
        file_name = './dataByNumber/' + str(csv_name)
        f = open(file_name, 'r')
        output = open('./dataResult/' + str(csv_name).split('_')
                      [-1][:-4] + '.txt', 'w')
        mutex = threading.Lock()
        ips = f.readlines()
        f.close()

        n = len(ips)
        cnt = 0

        thread_list = []

        initial_time = time.time()
        print('Started Working on %s at %s' %
              (csv_name, time.strftime("%Y-%m-%d %H:%M:%S.",
                                       time.localtime(initial_time + 3600 * 8))))
        # Time Zone of Beijing: GMT +8

        tbar = tqdm(total=n)

        for i in range(THREAD_NUMBER - 1):
            trace_thread = TraceThread(begin=i * (n // (THREAD_NUMBER - 1)),
                                       end=(i + 1) * (n // (THREAD_NUMBER - 1)),)
            trace_thread.start()
            thread_list.append(trace_thread)

        trace_thread = TraceThread(begin=n // (THREAD_NUMBER - 1) * (THREAD_NUMBER - 1),
                                   end=n)
        trace_thread.start()
        thread_list.append(trace_thread)

        for i in thread_list:
            i.join()

        finish_time = time.time()
        time.sleep(1)
        tbar.close()

        print('Finished Working on %s at %s' %
              (csv_name, time.strftime("%Y-%m-%d %H:%M:%S.",
                                       time.localtime(finish_time + 3600 * 8))))
        print('Time Cost: %s.' % datetime.timedelta(seconds=finish_time - initial_time))

        output.close()




