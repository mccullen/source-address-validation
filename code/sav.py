import warts
from warts.traceroute import Traceroute
from ipwhois.net import Net
from ipwhois.asn import IPASN, ASNOrigin
from pprint import pprint

class SAV():
    def find_sav_vulnerabilities(self, warts_file_path):

        with open('20180831.1535680800.warts', 'rb') as f:
            record = warts.parse_record(f)
            i_traceroute_records = 0
            blocked = set()
            not_blocked = set()
            customer_as_ids = set()
            privider_routers = set()
            vulnerable_routers = set()
            not_vulnerable_routers = set()
            n_cases = 0

            total = 0
            while record is not None and i_traceroute_records < 1000:
                while not isinstance(record, Traceroute):
                    record = warts.parse_record(f)
                i_traceroute_records += 1
                print("I: ", i_traceroute_records)
                addresses = [record.src_address] + list(map(lambda a: a.address, record.hops))
                for index, address in enumerate(addresses):
                    autonomous_system = self.get_as(address)
                    asn = autonomous_system['asn']
                    if asn == "NA":
                        as_id = self.get_as_id(autonomous_system)
                        customer_as_ids.add(as_id)
                        if index > 0 and index < len(addresses)-1:
                            # Stub is not first or last address
                            next_address = addresses[index+1]
                            prev_address = addresses[index-1]
                            privider_routers.add(next_address)
                            privider_routers.add(prev_address)
                            next_as = self.get_as(next_address)
                            total += 1
                            if index == len(addresses)-2:
                                #blocked.add(next_as['asn'])
                                blocked.add(self.get_as_id(autonomous_system))
                                not_vulnerable_routers.add(next_address)
                                print("blocked")
                            else:
                                #not_blocked.add(next_as['asn'])
                                not_blocked.add(self.get_as_id(autonomous_system))
                                vulnerable_routers.add(next_address)
                                print("not blocked")
                                n_cases += 1
                            print("n vulnerable: ", len(vulnerable_routers))
                            print("n not vulnerable: ", len(not_vulnerable_routers))
                            print("n providers: ", len(privider_routers))
                            print("n cases: ", n_cases)
                            print("n customers: ", len(customer_as_ids))

                        print(f"{index} of {len(addresses) -1}")

                record = warts.parse_record(f)

    def print_addresses(self, record):
        if record.src_address:
            print("Traceroute source address:", record.src_address)
        if record.dst_address:
            print("Traceroute destination address:", record.dst_address)

    def get_as(self, ip_address):
        net = Net(ip_address, allow_permutations=True)
        obj = IPASN(net)
        results = obj.lookup(inc_raw=True)
        #results['added'] = ASNOrigin(net).lookup(asn=results['asn'])

        #pprint(results)
        return results
    def get_as_id(self, record):
        return record["asn"] + record["asn_country_code"] + record["asn_date"]