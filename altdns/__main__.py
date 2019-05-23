#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# <3 silvio

import argparse
import threading
import time
import datetime
from threading import Lock
from Queue import Queue as Queue

import tldextract
from tldextract.tldextract import LOG
import logging
from termcolor import colored
import dns.resolver
import re
import os

logging.basicConfig(level=logging.CRITICAL)

def get_alteration_words(wordlist_fname):
    with open(wordlist_fname, "r") as f:
        return f.readlines()

# will write to the file if the check returns true
def write_domain(args, wp, full_url):
  wp.write(full_url)

# function inserts words at every index of the subdomain
def insert_all_indexes(args, alteration_words):
    with open(args.input, "r") as fp:
        with open(args.output_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index in range(0, len(current_sub)):
                        current_sub.insert(index, word.strip())
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not ".":
                            write_domain(args, wp, full_url)
                        current_sub.pop(index)
                    current_sub.append(word.strip())
                    actual_sub = ".".join(current_sub)
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    if len(current_sub[0]) > 0:
                      write_domain(args, wp, full_url)
                    current_sub.pop()

# adds word-NUM and wordNUM to each subdomain at each unique position
def insert_number_suffix_subdomains(args, alternation_words):
    with open(args.input, "r") as fp:
        with open(args.output_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in range(0, 10):
                    for index, value in enumerate(current_sub):
                        #add word-NUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + "-" + str(word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                        write_domain(args, wp, full_url)
                        current_sub[index] = original_sub

                        #add wordNUM
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + str(word)
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix)
                        write_domain(args, wp, full_url)
                        current_sub[index] = original_sub

# adds word- and -word to each subdomain at each unique position
def insert_dash_subdomains(args, alteration_words):
    with open(args.input, "r") as fp:
        with open(args.output_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[
                            index] + "-" + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if len(current_sub[0]) > 0 and actual_sub[:1] is not "-":
                            write_domain(args, wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + "-" + \
                            current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        if actual_sub[-1:] is not "-":
                            write_domain(args, wp, full_url)
                        current_sub[index] = original_sub

# adds prefix and suffix word to each subdomain
def join_words_subdomains(args, alteration_words):
    with open(args.input, "r") as fp:
        with open(args.output_tmp, "a") as wp:
            for line in fp:
                ext = tldextract.extract(line.strip())
                current_sub = ext.subdomain.split(".")
                for word in alteration_words:
                    for index, value in enumerate(current_sub):
                        original_sub = current_sub[index]
                        current_sub[index] = current_sub[index] + word.strip()
                        # join the list to make into actual subdomain (aa.bb.cc)
                        actual_sub = ".".join(current_sub)
                        # save full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(args, wp, full_url)
                        current_sub[index] = original_sub
                        # second dash alteration
                        current_sub[index] = word.strip() + current_sub[index]
                        actual_sub = ".".join(current_sub)
                        # save second full URL as line in file
                        full_url = "{0}.{1}.{2}\n".format(
                            actual_sub, ext.domain, ext.suffix)
                        write_domain(args, wp, full_url)
                        current_sub[index] = original_sub


def get_cname(q, target, resolved_out):
    global progress
    global lock
    global starttime
    global found
    global resolverName
    lock.acquire()
    progress += 1
    lock.release()
    if progress % 500 == 0:
        lock.acquire()
        left = linecount-progress
        secondspassed = (int(time.time())-starttime)+1
        amountpersecond = progress / secondspassed
        lock.release()
        seconds = 0 if amountpersecond == 0 else int(left/amountpersecond)
        timeleft = str(datetime.timedelta(seconds=seconds))
        print(
            colored("[*] {0}/{1} completed, approx {2} left".format(progress, linecount, timeleft),
                    "blue"))
    final_hostname = target
    result = list()
    result.append(target)
    resolver = dns.resolver.Resolver()
    if(resolverName is not None): #if a DNS server has been manually specified
        resolver.nameservers = [resolverName]
    try:
      for rdata in resolver.query(final_hostname, 'CNAME'):
        result.append(rdata.target)
    except:
        pass
    if len(result) is 1:
      try:
        A = resolver.query(final_hostname, "A")
        if len(A) > 0:
          result = list()
          result.append(final_hostname)
          result.append(str(A[0]))
      except:
        pass
    if len(result) > 1: #will always have 1 item (target)
        if str(result[1]) in found:
            if found[str(result[1])] > 3:
                return
            else:
                found[str(result[1])] = found[str(result[1])] + 1
        else:
            found[str(result[1])] = 1
        resolved_out.write(str(result[0]) + ":" + str(result[1]) + "\n")
        resolved_out.flush()
        ext = tldextract.extract(str(result[1]))
        if ext.domain == "amazonaws":
            try:
                for rdata in resolver.query(result[1], 'CNAME'):
                    result.append(rdata.target)
            except:
                pass
        print(
            colored(
                result[0],
                "red") +
            " : " +
            colored(
                result[1],
                "green"))
        if len(result) > 2 and result[2]:
            print(
                colored(
                    result[0],
                    "red") +
                " : " +
                colored(
                    result[1],
                    "green") +
                ": " +
                colored(
                    result[2],
                    "blue"))
    q.put(result)

def remove_duplicates(args):
  with open(args.output) as b:
    blines = set(b)
    with open(args.output, 'w') as result:
      for line in blines:
        result.write(line)

def remove_existing(args):
  with open(args.input) as b:
    blines = set(b)
  with open(args.output_tmp) as a:
    with open(args.output, 'w') as result:
      for line in a:
        if line not in blines:
          result.write(line)
  os.remove(args.output_tmp)

def get_line_count(filename):
    with open(filename, "r") as lc:
        linecount = sum(1 for _ in lc)
    return linecount


def main():
    q = Queue()

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="List of subdomains input", required=True)
    parser.add_argument("-o", "--output",
                        help="Output location for altered subdomains",
                        required=True)
    parser.add_argument("-w", "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False, default="words.txt")
    parser.add_argument("-r", "--resolve",
                        help="Resolve all altered subdomains",
                        action="store_true")
    parser.add_argument("-n", "--add-number-suffix",
                        help="Add number suffix to every domain (0-9)",
                        action="store_true")
    parser.add_argument("-e", "--ignore-existing",
                        help="Ignore existing domains in file",
                        action="store_true")
    parser.add_argument("-d", "--dnsserver",
                        help="IP address of resolver to use (overrides system default)", required=False)

    parser.add_argument(
        "-s",
        "--save",
        help="File to save resolved altered subdomains to",
        required=False)

    parser.add_argument("-t", "--threads",
                    help="Amount of threads to run simultaneously",
                    required=False, default="0")

    args = parser.parse_args()

    if args.resolve:
        try:
            resolved_out = open(args.save, "a")
        except:
            print("Please provide a file name to save results to "
                  "via the -s argument")
            raise SystemExit

    alteration_words = get_alteration_words(args.wordlist)

    # if we should remove existing, save the output to a temporary file
    if args.ignore_existing is True:
      args.output_tmp = args.output + '.tmp'
    else:
      args.output_tmp = args.output

    # wipe the output before, so we fresh alternated data
    open(args.output_tmp, 'w').close()

    insert_all_indexes(args, alteration_words)
    insert_dash_subdomains(args, alteration_words)
    if args.add_number_suffix is True:
      insert_number_suffix_subdomains(args, alteration_words)
    join_words_subdomains(args, alteration_words)

    threadhandler = []

    # Removes already existing + dupes from output
    if args.ignore_existing is True:
      remove_existing(args)
    else:
      remove_duplicates(args)

    if args.resolve:
        global progress
        global linecount
        global lock
        global starttime
        global found
        global resolverName       
        lock = Lock()
        found = {}
        progress = 0
        starttime = int(time.time())
        linecount = get_line_count(args.output)
        resolverName = args.dnsserver
        with open(args.output, "r") as fp:
            for i in fp:
                if args.threads:
                    if len(threadhandler) > int(args.threads):
                        #Wait until there's only 10 active threads
                        while len(threadhandler) > 10:
                           threadhandler.pop().join()
                try:
                    t = threading.Thread(
                        target=get_cname, args=(
                            q, i.strip(), resolved_out))
                    t.daemon = True
                    threadhandler.append(t)
                    t.start()
                except Exception as error:
                    print("error:"),(error)
            #Wait for threads
            while len(threadhandler) > 0:
               threadhandler.pop().join()
               
        timetaken = str(datetime.timedelta(seconds=(int(time.time())-starttime)))
        print(
            colored("[*] Completed in {0}".format(timetaken),
                    "blue"))

if __name__ == "__main__":
    main()
