
from __future__ import division
from __future__ import print_function
import argparse
import logging

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

#ADCS
from command.adcs.req import entry
from command.adcs.options import adcsoptions

#Nopac
from command.nopac.entry import NOPAC

#ZeroLogon
from command.zerologon.entry import ZEROLOGON

#PrintNightMare
from command.printnightmare import rprn_vector, par_vector
from command.printnightmare.entry import PRINTNIGHTMARE

def banner():
    return """

           _______      __    _        _____                                 
     /\   |  __ \ \    / /   | |      / ____|                                
    /  \  | |  | \ \  / /   _| |_ __ | (___   ___ __ _ _ __  _ __   ___ _ __ 
   / /\ \ | |  | |\ \/ / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  / ____ \| |__| | \  /| |_| | | | | |____) | (_| (_| | | | | | | |  __/ |   
 /_/    \_\_____/   \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_|_| |_|\___|_|                                                                              
    

[*]NoPAC:    
    > python main.py nopac redteam.com/user:123456 -dc-ip 10.10.10.10

[*]ZeroLogon:    
    > python main.py zerologon -dc-name WIN-AD -dc-ip 10.10.10.10

[*]CVE-2022–26923:  
    > python main.py adcs redteam.com/user:123456 -dc-ip 10.10.10.10 -target-ip 10.10.10.11 -ca WIN-AD-CA -template User

[*]PrintNightMare:    
    > python main.py printnightmare redteam.com/user:123456 -target-ip 10.10.10.10

    """

def parse_arguments():
    parser = argparse.ArgumentParser(description="ADVulnScanner v0.0.1")

    subparsers = parser.add_subparsers(dest="vuln_type")
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')


    # 漏洞 A 参数
    parser_a = subparsers.add_parser("nopac", help="Scan NoPAC")
    parser_a.add_argument('credentials', action='store', help='domain/username[:password]')
    parser_a.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    parser_a.add_argument('-dc-ip', action='store', metavar="ip address", required=True, help='IP Address of the domain controller.')
    parser_a.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')


    # 漏洞 B 参数
    parser_b = subparsers.add_parser("zerologon", help="Scan ZeroLogon")
    parser_b.add_argument('-dc-name', action="store", metavar="dns netbios name", help='NetBIOS name of the domain controller')
    parser_b.add_argument("-u", "--user", dest='username', metavar='', help="authenticated domain user,may be required for SMB", type=str,default="")
    parser_b.add_argument("-d", "--domain", dest='domain', metavar='', help="domain name, required only when authentication over SMB", type=str, default="")
    parser_b.add_argument("-p", "--pass", dest='password', metavar='', help="authenticated domain user's password, may be required for SMB", type=str,default="")
    parser_b.add_argument('-dc-ip', action='store', metavar="ip address", required=True, help='IP Address of the domain controller.')
    parser_b.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')


    # 漏洞 C 参数
    parser_c = subparsers.add_parser("adcs", help="Scan CVE-2022-26923")
    parser_c.add_argument('credentials', action='store', help='domain/username[:password]')
    parser_c.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    parser_c.add_argument('-ca', action="store", metavar="ca name", help='certificate authority name')
    parser_c.add_argument('-dc-ip', action='store', metavar="ip address", required=True, help='IP Address of the domain controller.')
    parser_c.add_argument('-target-ip', action="store", metavar="target ip", help='DNS Name or IP Address of the target machine.')
    parser_c.add_argument('-template', action="store", metavar="template name", help='template name User or Machine.')
    parser_c.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    # 漏洞 D 参数
    parser_d = subparsers.add_parser("printnightmare", help="Scan PrintNightMare")
    parser_d.add_argument('credentials', action='store', help='domain/username[:password]')
    parser_d.add_argument('-target-ip', action="store", metavar="target ip", help='DNS Name or IP Address of the target machine.')
    parser_d.add_argument("-t", "--timeout", type=int, default=10, help="timeout (default: 10s)")
    parser_d.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')


    args = parser.parse_args()
    return args

def main():
    args = parse_arguments()

    if args.vuln_type is None:
        print("Error: You must provide a vuln_type.")
        parser = argparse.ArgumentParser()
        parser.print_help()


    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
    

    if args.vuln_type == "nopac":
        print("[*] Start Check Nopac at : %s" % args.dc_ip)
        try:

            domain, username, password = parse_credentials(args.credentials)

            dumper = NOPAC(username, username, password, domain, args.hashes, args.dc_ip)
            dumper.dump()

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
            logging.error(str(e))
    
    elif args.vuln_type == "zerologon":
        print("[*] Start Check ZeroLogon at : %s" % args.dc_ip)

        try:

            zerologon = ZEROLOGON('\\\\' + args.dc_name, args.username, args.password, args.domain, args.dc_name, args.dc_ip, test_type='rpc', privacy=True)
            zerologon.perform_attack()

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
            logging.error(str(e))

    elif args.vuln_type == "adcs":
        
        print("[*] Start Check CVE-2022-26923 at : %s" % args.dc_ip)

        try:

            domain, username, password = parse_credentials(args.credentials)

            Adcsoptions = adcsoptions()
            Adcsoptions.ca = args.ca
            Adcsoptions.dc_ip = args.dc_ip
            Adcsoptions.hashes = args.hashes
            Adcsoptions.key_size = 2048
            Adcsoptions.ns = args.dc_ip
            Adcsoptions.password = password
            Adcsoptions.target = args.target_ip
            Adcsoptions.target_ip = args.target_ip
            Adcsoptions.template = args.template
            Adcsoptions.username = username
        
            entry(Adcsoptions)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
            logging.error(str(e))

    elif args.vuln_type == "printnightmare":

        domain, username, password = parse_credentials(args.credentials)
        printbug = PRINTNIGHTMARE()
        printbug.check(rprn_vector, username, password, domain, args.target_ip, 445, args.timeout)
        printbug.check(par_vector, username, password, domain, args.target_ip, 445, args.timeout)


if __name__ == '__main__':
    logger.init()
    print(banner())
    main()

