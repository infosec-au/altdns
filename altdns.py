#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# <3 silvio

import argparse
import threading
from Queue import Queue as Queue

import tldextract
from termcolor import colored
import dns.resolver


def get_alteration_words(wordlist_fname):
    with open(wordlist_fname, "r") as f:
        return f.readlines()


# function inserts words at every index of the subdomain
def insert_all_indexes(args, alteration_words):
    with open(args.input, "r") as fp, open(args.output, "a") as wp:
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
                    wp.write(full_url)
                    current_sub.pop(index)
                current_sub.append(word.strip())
                actual_sub = ".".join(current_sub)
                full_url = "{0}.{1}.{2}\n".format(
                    actual_sub, ext.domain, ext.suffix)
                wp.write(full_url)
                current_sub.pop()

# adds word- and -word to each subdomain at each unique position


def insert_dash_subdomains(args, alteration_words):
    with open(args.input, "r") as fp, open(args.output, "a") as wp:
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
                    wp.write(full_url)
                    current_sub[index] = original_sub
                    # second dash alteration
                    current_sub[index] = word.strip() + "-" + \
                        current_sub[index]
                    actual_sub = ".".join(current_sub)
                    # save second full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    wp.write(full_url)
                    current_sub[index] = original_sub


# adds prefix and suffix word to each subdomain
def join_words_subdomains(args, alteration_words):
    with open(args.input, "r") as fp, open(args.output, "a") as wp:
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
                    wp.write(full_url)
                    current_sub[index] = original_sub
                    # second dash alteration
                    current_sub[index] = word.strip() + current_sub[index]
                    actual_sub = ".".join(current_sub)
                    # save second full URL as line in file
                    full_url = "{0}.{1}.{2}\n".format(
                        actual_sub, ext.domain, ext.suffix)
                    wp.write(full_url)
                    current_sub[index] = original_sub


def get_cname(q, target, resolved_out):
    global progress
    progress += 1
    if progress % 500 == 0:
        print(
            colored("[*] {0}/{1} completed".format(progress, linecount),
                    "blue"))
    final_hostname = target
    result = list()
    result.append(target)
    try:
        for rdata in dns.resolver.query(final_hostname, 'CNAME'):
            result.append(rdata.target)
        if result is not None:
            resolved_out.write(str(result[0]) + ":" + str(result[1]) + "\n")
            resolved_out.flush()
            ext = tldextract.extract(str(result[1]))
            if ext.domain == "amazonaws":
                try:
                    for rdata in dns.resolver.query(result[1], 'CNAME'):
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
    except dns.exception.DNSException:
        pass


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

    parser.add_argument(
        "-s",
        "--save",
        help="File to save resolved altered subdomains to",
        required=False)

    args = parser.parse_args()

    if args.resolve:
        try:
            resolved_out = open(args.save, "a")
        except:
            print("Please provide a file name to save results to "
                  "via the -s argument")
            raise SystemExit

    alteration_words = get_alteration_words(args.wordlist)
    insert_all_indexes(args, alteration_words)
    insert_dash_subdomains(args, alteration_words)
    join_words_subdomains(args, alteration_words)

    if args.resolve:
        global progress
        global linecount
        progress = 0
        linecount = get_line_count(args.output)
        with open(args.output, "r") as fp:
            for i in fp:
                try:
                    t = threading.Thread(
                        target=get_cname, args=(
                            q, i.strip(), resolved_out))
                    t.daemon = True
                    t.start()
                except Exception as error:
                    print("error: " + error)

if __name__ == "__main__":
    main()
