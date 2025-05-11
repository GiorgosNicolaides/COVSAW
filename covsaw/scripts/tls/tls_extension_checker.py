from covsaw.scripts.tls.tls_base import TLSChecker
from cryptography import x509

class TLSExtensionChecker(TLSChecker):
    NAME = 'extension'

    def run_check(self):
        issues = []
        cert = self.leaf

        # 1) Key Usage
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not (ku.digital_signature or ku.key_encipherment):
                issues.append(('missing_key_usage',
                    "Neither digitalSignature nor keyEncipherment set"))
        except x509.ExtensionNotFound:
            issues.append(('no_key_usage', "KeyUsage extension missing"))

        # 2) Extended Key Usage
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if x509.ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                issues.append(('missing_eku', "No serverAuth EKU"))
        except x509.ExtensionNotFound:
            issues.append(('no_eku', "ExtendedKeyUsage extension missing"))

        # 3) CRL DP and AIA
        for ext_cls, code in [
            (x509.CRLDistributionPoints, 'no_crl_dp'),
            (x509.AuthorityInformationAccess, 'no_aia')
        ]:
            try:
                cert.extensions.get_extension_for_class(ext_cls)
            except x509.ExtensionNotFound:
                issues.append((code, f"{ext_cls.__name__} missing"))

        return issues

    def summary(self):
        cert = self.leaf
        kus = []
        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if ku.digital_signature:    kus.append('digitalSignature')
            if ku.key_encipherment:     kus.append('keyEncipherment')
        except x509.ExtensionNotFound:
            pass

        ekus = []
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            ekus = [oid._name for oid in eku]
        except x509.ExtensionNotFound:
            pass

        has_crl = True
        try:
            cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        except x509.ExtensionNotFound:
            has_crl = False
        has_aia = True
        try:
            cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        except x509.ExtensionNotFound:
            has_aia = False

        msg = (f"KeyUsage={kus or 'none'}; EKU={ekus or 'none'}; "
               f"CRLDP={'yes' if has_crl else 'no'}; AIA={'yes' if has_aia else 'no'}")
        return ('ok', msg)
