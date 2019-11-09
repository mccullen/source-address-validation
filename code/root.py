from sav import SAV


class Root():
    def find_sav_vulnerabilities(self):
        validator = SAV()
        warts_file_path = '20180831.1535680800.warts'
        validator.find_sav_vulnerabilities(warts_file_path)
    def get_asn(self, ip_address):
        validator = SAV()
        return validator.get_as(ip_address)