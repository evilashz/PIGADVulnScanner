
from __future__ import division
from __future__ import print_function

import logging

handler = logging.StreamHandler()
handler.setFormatter(
    logging.Formatter(
        style="{",
        fmt="[{name}] {levelname} - {message}"
    )
)

log = logging.getLogger("entry")
log.setLevel(logging.INFO)
log.addHandler(handler)

class PRINTNIGHTMARE:


    def check(self, vector, username, password, domain, address, port, timeout, share="\\\\{0}\\wpscheck\\bogus.dll"):
        results = {
            "address": address,
            "protocol": vector.PROTOCOL,
            "vulnerable": False,
            "reason": ""
        }

        try:

            dce = vector.connect(
                username,
                password,
                domain,
                "",
                "",
                address,
                port,
                timeout
            )

        except Exception as e:
            log.debug(e)
            if str(e).find("ept_s_not_registered") != -1 or str(e).find("STATUS_OBJECT_NAME_NOT_FOUND") != -1:
                log.info(f"{address} is not vulnerable over {vector.PROTOCOL}. Reason: Print Spooler service is not running or inbound remote printing is disabled.")
                results["vulnerable"] = False
                results["Reason"] = "Response indicates the Print Spooler Service is not running or inbound remote printing is disabled"
            else:
                log.info(f"Unable to determine if {address} is vulnerable over {vector.PROTOCOL}. Reason: {e}")
                results["vulnerable"] = "Unknown"
                results["reason"] = str(e)

        else:
            local_ip = dce.get_rpc_transport().get_socket().getsockname()[0]
            share = share.format(local_ip)
            #share = f"\\\\192.168.3.1\\itwasalladream\\bogus.dll"

            try:
                blob = vector.getDrivers(dce)
                pDriverPath = str(pathlib.PureWindowsPath(blob['DriverPathArray']).parent) + '\\UNIDRV.DLL'
                if not ("FileRepository" in pDriverPath):
                    log.error(f"pDriverPath {pDriverPath}, expected ':\\Windows\\System32\\DriverStore\\FileRepository\\...")
                    raise AutomaticDriverEnumerationError
            except Exception as e:
                log.error(f"Failed to enumerate remote pDriverPath, unable to determine if host is vulnerable. Error: {e}")
                results["vulnerable"] = "unknown"
                results["reason"] = f"Unkown error while trying to automatically enumerate printer drivers: '{e}'"

            except AutomaticDriverEnumerationError as e:
                log.error("Failed to automatically enumerate printer drivers, unable to determine if host is vulnerable.")
                results["vulnerable"] = "unknown"
                results["reason"] = "Got unexpected value when trying to automatically enumerate printer drivers (this is necessary for the exploit to succeed)"

            else:
                log.debug(f"pDriverPath found: {pDriverPath}")
                log.debug(f"Attempting DLL execution {share}")

                try:
                    vector.exploit(dce, pDriverPath, share)
                except Exception as e:
                    log.debug(e)
                    # Spooler Service attempted to grab the DLL, host is vulnerable
                    if str(e).find("ERROR_BAD_NETPATH") != -1:
                        log.info(f"{address} is vulnerable over {vector.PROTOCOL}. Reason: Host attempted to grab DLL from supplied share")
                        results["vulnerable"] = True
                        results["reason"] = "Host attempted to grab DLL from supplied share"

                    elif str(e).find("ERROR_INVALID_PARAMETER") != -1:
                        log.info(f"{address} is vulnerable over {vector.PROTOCOL}. Reason: Response indicates host has the CVE-2021-34527 patch applied *but* has Point & Print enabled. Re-trying with known UNC bypass to validate.")
                        results = check(vector, username, password, domain, address, port, timeout, share="\\??\\UNC\\{0}\\wpscheck\\bogus.dll")
                        results["reason"] = f"{address} is vulnerable over {vector.PROTOCOL}. Reason: Response indicates host has the CVE-2021-34527 patch applied *but* has Point & Print enabled."

                    #elif str(e).find("ERROR_INVALID_HANDLE") != -1:
                    #    log.debug("Got invalid handle.. trying again")
                    #    continue

                    elif str(e).find("rpc_s_access_denied") != -1:
                        log.info(f"{address} is not vulnerable over {vector.PROTOCOL}. Reason: RPC call returned access denied. This is usually an indication the host has been patched *and* Point & Print is disabled.")
                        results["vulnerable"] = False
                        results["reason"] = "RPC call returned access denied. This is usually an indication the host has been patched."

                    else:
                        log.info(f"Unable to determine if {address} is vulnerable over {vector.PROTOCOL}. Got unexpected response: {e}")
                        results["vulnerable"] = "Unknown"
                        results["reason"] = f"Unable to determine if host is vulnerable. Got unexpected response: {e}"
                else:
                    log.info(f"{address} is vulnerable over {vector.PROTOCOL}. Reason: Host copied the DLL you're hosting.")
                    results["vulnerable"] = True
                    results["reason"] = "Reason: Host copied the DLL you're hosting."

        return results