import configparser
import socket
import time
from threading import Thread
import dnslib
import pickle
import itertools


class CachingDNSServer:
    def __init__(self, forward_dns):
        self.forward_dns = forward_dns
        self.try_retrieve_cache()
        thread = Thread(target=self.filter_cache, args=[1])
        thread.daemon = True
        thread.start()

    def try_retrieve_cache(self):
        try:
            with open(cache_filename, 'rb') as file:
                self.cache = pickle.load(file)
            print("кеш загружен из файла " + cache_filename)
        except:
            self.cache = list()
        print(self.cache)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        # sock_forward_dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # sock_forward_dns.settimeout(1)
        sock.bind(('', 53))
        while True:
            try:
                query, address = sock.recvfrom(1024)
            except socket.timeout:
                continue
            print(repr(dnslib.DNSRecord.parse(query)))
            ans = self.try_get_from_cache(query)
            if not ans:
                print("not found in cache")
                try:
                    sock.sendto(query, (self.forward_dns, 53))
                    ans = sock.recv(1024)
                    self.save_to_cache(ans)
                except (socket.timeout, socket.error):
                    ans = b""
            else:
                print("cached")
            sock.sendto(ans, address)

    def try_get_from_cache(self, query):
        parsed_query = dnslib.DNSRecord.parse(query)
        if parsed_query.q.qtype != 1 and parsed_query.q.qtype != 2:
            return
        # print(self.cache[0][1].rtype)
        # print(parsed_query.q.qtype)
        entries = [entry for entry in self.cache if entry[0] == str(parsed_query.q.qname)
                   and entry[1].rtype == parsed_query.q.qtype
                   and entry[2] > time.time()]
        print(entries)
        if not entries:
            return
        answer = dnslib.DNSRecord(q=parsed_query.q, header=dnslib.DNSHeader(qr=1, id=parsed_query.header.id))
        for entry in entries:
            answer.add_answer(dnslib.RR(rname=entry[1].rname, rtype=entry[1].rtype,
                                        rclass=entry[1].rclass, rdata=entry[1].rdata,
                                        ttl=int(entry[2]-time.time())))
        print(repr(answer))
        return bytes(answer.pack())

    def save_to_cache(self, answer):
        parsed_answer = dnslib.DNSRecord.parse(answer)
        for record in itertools.chain(parsed_answer.rr, parsed_answer.ar, parsed_answer.auth):
            print((str(record.get_rname()), record, time.time() + record.ttl))
            self.cache.append((str(record.get_rname()), record, time.time() + record.ttl))

    def filter_cache(self, delay):
        """
        удаляет записи с истекшим ттл
        :param delay:
        :return:
        """
        while True:
            time.sleep(delay)
            for entry in self.cache[:]:
                if entry[2] < time.time():
                    self.cache.remove(entry)


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("config.ini")
    forward_dns = config["FORWARD SERVER"]["ip"]
    cache_filename = "cache.txt"

    dns = CachingDNSServer(forward_dns)
    try:
        dns.start()
    except KeyboardInterrupt:
        print("KeyboardInterrupt")
        with open(cache_filename, 'wb') as f:
            pickle.dump(dns.cache, f)
        print(dns.cache)
        print("кеш сохранен в " + cache_filename)

