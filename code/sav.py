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
            n_vulnerable = 0
            vulnerable_as = set()
            vulnerable_ip = set()
            all_ip = set()
            while record is not None and i_traceroute_records < 1000:
                while not isinstance(record, Traceroute):
                    record = warts.parse_record(f)
                i_traceroute_records += 1
                print("I: ", i_traceroute_records)
                #print_addresses(record)
                #print("Number of hops:", len(record.hops))
                #print(record.hops)
                addresses = [record.src_address] + list(map(lambda a: a.address, record.hops))
                for index, address in enumerate(addresses):
                    #print("address: ", address)
                    autonomous_system = self.get_as(address)
                    asn = autonomous_system['asn']
                    #print(autonomous_system)
                    if asn == "NA":
                        all_ip.add(address)
                        #if index > 0 and index < len(addresses)-1:
                        #    # Stub is not first or last address
                        #    provider_address = addresses[index-1]
                        #    next_address = addresses[index+1]
                        #    if provider_address == next_address:
                        #        print("Found loop!")
                        #print(f"{index} of {len(addresses) -1}")

                        if index <= len(addresses)-1:
                            if index == len(addresses)-1:
                                print("Good")
                            else:
                                remainder = addresses[index+1:]
                                found = False
                                i_r = 0
                                while not found and i_r < len(remainder):
                                    as2 = self.get_as(remainder[i_r])
                                    if as2['asn'] != "NA":
                                        found = True
                                        found = False
                                    i_r += 1
                                if found == True:
                                    print("Found vulnerability")
                                    vulnerable_ip.add(address)
                                else:
                                    print("Good")


                        #if index == len(addresses)-1:
                        #    print("Good")
                        #else:
                        #    print("Found vulnerability")


                record = warts.parse_record(f)
            print(f"all ip: {len(all_ip)}")
            print(f"vul ip: {len(vulnerable_ip)}")

    def print_addresses(self, record):
        if record.src_address:
            print("Traceroute source address:", record.src_address)
        if record.dst_address:
            print("Traceroute destination address:", record.dst_address)

    def get_as(self, ip_address):
        net = Net(ip_address, allow_permutations=True)
        obj = IPASN(net)
        results = obj.lookup(inc_raw=True)
        #pprint(results)
        return results