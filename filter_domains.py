#!/usr/bin/env python3

import os
import errno

FIFO = 'phishing_catcher-pipe'
FILE = 'suspicious_domains.log'

try:
    os.mkfifo(FIFO)
except OSError as oe:
    if oe.errno != errno.EEXIST:
        raise

while True:
    with open(FIFO) as fifo:
        while True:
            domain_fifo = fifo.read()
            domain_to_find = domain_fifo.rstrip('\n')
            if len(domain_to_find) == 0:
                break
            is_domain_known = False
            with open(FILE, 'r', buffering=1, encoding='UTF-8') as known_domains_read:
                for domain in known_domains_read:
                    if domain.rstrip('\n') == domain_to_find:
                        print("Found known domain: {}".format(domain_to_find))
                        is_domain_known = True
                        break
            if is_domain_known == False:
                with open(FILE, 'a', buffering=1, encoding='UTF-8') as known_domains_write:
                    known_domains_write.write(domain_to_find + "\n")
                    print("Found new domain: {}".format(domain_to_find))
