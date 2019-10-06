#  Python 3 script to perform whois on list of targets to identify the owner
#  by @xFreed0m

import sys
import whois
import argparse
import datetime
import logging
import csv
from colorlog import ColoredFormatter


Logger = None


def args_parse():
    parser = argparse.ArgumentParser()
    targets_group = parser.add_mutually_exclusive_group(required=True)
    targets_group.add_argument('-u', '--url', help="Single URL to query")
    targets_group.add_argument('-U', '--urllist', help="File containing URLs, one per line")
    parser.add_argument('-o', '--output', help="Output each whois query result to a csv file",
                        default="Whoiser")
    return parser.parse_args()


def configure_logger():  # This function is responsible to configure logging object.

    global LOGGER
    LOGGER = logging.getLogger("Whoiser")
    # Set logging level
    try:
        LOGGER.setLevel(logging.DEBUG)
    except Exception as logger_err:
        exception(logger_err)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)

    # Create log-file handler
    log_filename = "Whoiser." + datetime.datetime.now().strftime('%d-%m-%Y') + '.log'
    fh = logging.FileHandler(filename=log_filename, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def exception(incoming_err):
    LOGGER.critical("[!] Exception: " + str(incoming_err))


def banner():
    print("""
                       _______ _________ _______  _______  _______
    |\     /||\     /|(  ___  )\__   __/(  ____ \(  ____ \(  ____ )
    | )   ( || )   ( || (   ) |   ) (   | (    \/| (    \/| (    )|
    | | _ | || (___) || |   | |   | |   | (_____ | (__    | (____)|
    | |( )| ||  ___  || |   | |   | |   (_____  )|  __)   |     __)
    | || || || (   ) || |   | |   | |         ) || (      | (\ (
    | () () || )   ( || (___) |___) (___/\____) || (____/\| ) \ \__
    (_______)|/     \|(_______)\_______/\_______)(_______/|/   \__/
    \n
    By @x_Freed0m
    """)


def url_list_maker(urllist_arg):
    with open(urllist_arg) as url_object:
        return [u.strip() for u in url_object.readlines()]


def output(target, domain, registrar, emails, name, organization, output_file_name):
    try:
        with open(output_file_name + ".csv", mode='a') as log_file:
            creds_writer = csv.writer(log_file, delimiter=',', quotechar='"')
            creds_writer.writerow([target, domain, registrar, emails, name, organization])
    except Exception as output_err:
        exception(output_err)


def whoiser(targets, output_file_name):
    output('Target', 'Domain', 'Registrar', 'Emails', 'Name', 'Organization', output_file_name)
    for t in targets:
        try:
            w = whois.whois(t)
            LOGGER.info("[+] Querying: %s" % t)
            LOGGER.info("[*] ***************************")
            LOGGER.info("[+] Domain: " + str(w.domain_name))
            LOGGER.info("[+] Registrar: " + str(w.registrar))
            LOGGER.info("[+] Emails: " + str(w.emails))
            LOGGER.info("[+] Name: " + str(w.name))
            LOGGER.info("[+] Organization: " + str(w.org) + "\n")
            output(str(t), str(w.domain_name), str(w.registrar), str(w.emails), str(w.name),
                   str(w.org), output_file_name)
        except whois.parser.PywhoisError as e:
            LOGGER.warning("Domain %s seems to be NOT registered" % t)
            exception(e)
        except KeyboardInterrupt:
            LOGGER.critical("[!] [CTRL+C] Stopping the tool")
            exit(1)
        except Exception as err:
            exception(err)


def main():
    configure_logger()
    banner()
    args = args_parse()

    if args.urllist:
        url_list = url_list_maker(args.urllist)
        whoiser(url_list, args.output)
    else:
        url_list = [args.url]
        whoiser(url_list, args.output)


if __name__ == '__main__':
    main()
