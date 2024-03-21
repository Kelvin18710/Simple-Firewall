class SimpleFirewall:
    def __init__(self):
        self.blacklist = set()
        self.whitelist = set()

    def add_to_blacklist(self, ip):
        self.blacklist.add(ip)

    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)

    def is_allowed(self, ip):
        return ip not in self.blacklist