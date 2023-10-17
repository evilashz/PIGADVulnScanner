

class adcsoptions:
    
    def __init__(self):
        self.aes: str = None
        self.archive_key: bool = False
        self.ca: str = None
        self.dc_ip: str = None
        self.debug=False
        self.dns: str = None
        self.dns_tcp: bool = False
        self.do_kerberos: bool = False
        self.dynamic_endpoint: bool = False
        self.hashes: str = None
        self.key_size: int = None
        self.no_pass: bool = False
        self.ns: str = None
        self.on_behalf_of: str = None
        self.out: str = None
        self.password: str = None
        self.pfx: str = None
        self.port: int = None
        self.renew: bool = False
        self.retrieve: int = 0
        self.scheme: str = 'http'
        self.sid: str = None
        self.subject: str = None
        self.target: str = None
        self.target_ip: str = None
        self.template: str = None
        self.timeout: int = 5
        self.upn: str = None
        self.use_sspi: bool = False
        self.username: str = None
        self.web: bool = False