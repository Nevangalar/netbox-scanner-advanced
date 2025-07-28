import nmap3

class Nmap(object):

    def __init__(self, unknown, networks):
        self.unknown = unknown
        self.networks = networks
        self.hosts = list()
        self.scan_results = {}

    def scan(self):
        nmap = nmap3.NmapHostDiscovery()  # instantiate nmap object
        for item in self.networks:
            temp_scan_result = nmap.nmap_no_portscan(item.replace('\n', ''), args="-R --system-dns")
            self.scan_results = {**self.scan_results, **temp_scan_result}
            self.scan_results.pop("stats", None)
            self.scan_results.pop("runtime", None)
        return self.scan_results

    def run(self):
        scan_results = self.scan()
        for k, v in scan_results.items():
            try:
                hostname = v['hostname'][0]['name'] if v['hostname'] else self.unknown
                mac = v['macaddress'] if 'macaddress' in v else None
                self.hosts.append((k, hostname, mac))
            except (IndexError, KeyError):
                self.hosts.append((k, self.unknown, None))
