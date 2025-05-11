from covsaw.scripts.tls.tls_base import TLSChecker
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

class TLSCertificateChecker(TLSChecker):
    NAME = 'certificate'

    def run_check(self):
        issues = []
        cert = self.leaf
        now = datetime.datetime.utcnow()

        # 1) Validity period
        if cert.not_valid_before > now:
            issues.append(('not_yet_valid',
                f"Not valid until {cert.not_valid_before.isoformat()}"))
        if cert.not_valid_after < now:
            issues.append(('expired',
                f"Expired at {cert.not_valid_after.isoformat()}"))

        # 2) Hostname match (CN + SAN)
        names = []
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            names += san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        try:
            cn = cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value
            names.append(cn)
        except IndexError:
            pass

        if self.host not in names:
            issues.append(('hostname_mismatch',
                f"{self.host} not in certificate names {names}"))

        # 3) Issuer trust
        if self.trusted_ca_file:
            issuer = cert.issuer.rfc4514_string()
            trusted = False
            try:
                with open(self.trusted_ca_file, encoding='utf-8') as f:
                    for line in f:
                        if line.strip() and line.strip() in issuer:
                            trusted = True
                            break
            except IOError:
                issues.append(('trusted_ca_file_error',
                    f"Cannot read trust file {self.trusted_ca_file}"))
            if not trusted:
                issues.append(('untrusted_issuer',
                    f"Issuer {issuer} not found in trust file"))

        return issues

    def summary(self):
        cert = self.leaf
        nb = cert.not_valid_before.isoformat()
        na = cert.not_valid_after.isoformat()
        # reuse parsing from run_check
        names = []
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
            names += san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        try:
            cn = cert.subject.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value
            names.append(cn)
        except IndexError:
            pass

        issuer = cert.issuer.rfc4514_string()
        msg = (f"Valid {nb} → {na}; Names={names}; "
               f"Issuer='{issuer[:60]}…'")
        return ('ok', msg)
