# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import io
import os
import sys
import re
import socket
import struct
import ssl
from datetime import datetime
from streams import ByteStream, SocketStream

# Import non-standard modules
try:
    from cryptography import exceptions
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, hmac, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("Cryptography module not found; try 'pip install cryptography'")


PURPOSE = """\
Create a TLS connection

tls1.2-test.py client | server

  client   connect to various websites with TLS
  server   act as a server and listen for TLS connection
"""


CONFIGURATION = {
    "certificate_path": "",
    "test_sites": ["google.com", "amazon.com", "facebook.com"]
}


class PKICertificate:

    @staticmethod
    def load_system_certs():
        if not PKICertificate.__system_certs_loaded:
            for cert_bytes, encoding_type, trust in ssl.enum_certificates("ROOT") + ssl.enum_certificates("CA"):
                PKICertificate().load_from_der(cert_bytes, trust)
            PKICertificate.__system_certs_loaded = True

    def __init__(self):
        self.cert = None
        self.identifier = None
        self.is_trusted = False

    def get_identifier(self):
        return self.identifier

    def load_from_der(self, der_data, trust=None):
        self.cert = x509.load_der_x509_certificate(bytes(der_data), default_backend())
        self.is_trusted = trust is True or (trust is not None and x509.oid.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string in trust)
        try:
            self.identifier = self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            pass
        except ValueError:
            pass

    def load_from_pem(self, pem_data):
        self.cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        try:
            self.identifier = self.cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        except x509.ExtensionNotFound:
            pass

    def get_public_key(self):
        return self.cert.public_key()

    def get_public_bytes(self):
        return self.cert.public_bytes(Encoding.DER)

    def get_issuer(self):
        try:
            issuer = self.cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
            return issuer.value.key_identifier
        except x509.ExtensionNotFound:
            return None

    def get_signature(self):
        return self.cert.signature

    def get_tbs_certificate_bytes(self):
        return self.cert.tbs_certificate_bytes

    def get_signature_hash_algorithm(self):
        return self.cert.signature_hash_algorithm

    def validate(self, host=None):

        # Ensure the version identifier is legal
        if self.cert.version != x509.Version.v3:
            return False

        # Ensure the certificate is current
        now = datetime.utcnow()
        if now < self.cert.not_valid_before or now > self.cert.not_valid_after:
            return False

        # If a host name wasn't specified then we've done as much as we can
        if host is None:
            return True

        # Extract all subject names from the certificate
        common_names = self.cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        subject_names = [common_names[0].value]
        try:
            san = self.cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = san.value.get_values_for_type(x509.DNSName)
            subject_names.extend(names)
            subject_names = set(subject_names)
        except x509.ExtensionNotFound:
            pass

        # Try to match the host name to a subject name
        host_labels = host.lower().split(".")
        host_labels.reverse()
        for subject_name in subject_names:
            subject_labels = subject_name.split(".")

            # The subject name must have the same number of labels as the host name
            if len(subject_labels) != len(host_labels):
                continue

            # All labels up to the left-most label must match exactly
            parts_mismatch = False
            subject_labels.reverse()
            for i in range(len(host_labels) - 1):
                if subject_labels[i] != host_labels[i]:
                    parts_mismatch = True
                    break
            if parts_mismatch:
                continue

            # The left-most label must match exactly or be a wildcard
            if subject_labels[-1] != host_labels[-1] and subject_labels[-1] != "*":
                continue

            # If we matched a wildcard then apply some more checks
            if subject_labels[-1] == "*":
                if len(subject_labels) < 3:
                    continue

            # We found a match so return success
            return True

        # No match was found for the host name
        return False


class PKICertificateStore:

    _root_store = None          # Windows Trusted Root Certification Authorities
    _ca_store = None            # Windows Intermediate Certification Authorities

    # Enumeration for certificate validation
    CERT_INVALID = 0
    CERT_SELF_SIGNED = 1
    CERT_CA_SIGNED = 2

    def __init__(self, parent_store=None):
        self.certificates = {}
        self.parent_store = parent_store
        self.first_cert = None

    @staticmethod
    def get_root_store():
        if PKICertificateStore._root_store is None:
            PKICertificateStore._root_store = PKICertificateStore.load_system_store("ROOT")
        return PKICertificateStore._root_store

    @staticmethod
    def get_ca_store():
        if PKICertificateStore._ca_store is None:
            # The parent of the CA store is the ROOT store
            root_store = PKICertificateStore.get_root_store()
            PKICertificateStore._ca_store = PKICertificateStore.load_system_store("CA", root_store)
        return PKICertificateStore._ca_store

    @staticmethod
    def load_system_store(name, parent_store=None):
        store = PKICertificateStore(parent_store)
        for cert_bytes, encoding_type, trust in ssl.enum_certificates(name):
            cert = PKICertificate()
            cert.load_from_der(cert_bytes, trust)
            store.add(cert)
        return store

    def add(self, cert):
        identifier = cert.get_identifier()
        if identifier is not None:
            if self.first_cert is None:
                self.first_cert = cert
            self.certificates[identifier] = cert

    def get_first_cert(self):
        return self.first_cert

    def find(self, identifier):
        # returns the cert if found, and the store it belongs to
        if identifier in self.certificates:
            return self.certificates[identifier], self
        elif self.parent_store is not None:
            return self.parent_store.find(identifier)
        else:
            return None, None

    def validate_chain(self, cert, host):
        # Validate the certificate
        if not cert.validate(host):
            return PKICertificateStore.CERT_INVALID

        # Walk certificate chain to validate
        return self._walk_chain(cert)

    def _walk_chain(self, cert):

        # Find the issuer certificate
        issuer_identifier = cert.get_issuer()
        issuer_cert, issuer_store = self.find(issuer_identifier)
        if issuer_cert is None:
            return PKICertificateStore.CERT_INVALID

        # If the issuer identifier is the same as the cert identifier then we've reached the top of the chain
        if cert.get_identifier() == issuer_cert.get_identifier():

            # Look for the top cert in the trusted stores
            ca_store = PKICertificateStore.get_ca_store()
            trusted_cert, trusted_store = ca_store.find(issuer_identifier)

            # TODO: is this accurate?
            # If the top of the chain is not in a trusted store then it's self-signed
            if trusted_cert is None:
                return PKICertificateStore.CERT_SELF_SIGNED

            # Validate the trusted cert just in case
            if not trusted_cert.validate():
                return PKICertificateStore.CERT_INVALID

            return PKICertificateStore.CERT_CA_SIGNED

        # Validate the issuer certificate
        if not issuer_cert.validate():
            return PKICertificateStore.CERT_INVALID

        # Ensure this certificate was signed by the issuer certificate
        issuer_public_key = issuer_cert.get_public_key()
        try:
            issuer_public_key.verify(cert.get_signature(), cert.get_tbs_certificate_bytes(), padding.PKCS1v15(), cert.get_signature_hash_algorithm())
        except exceptions.InvalidSignature:
            return PKICertificateStore.CERT_INVALID

        # If the issuer certificate is trusted then we're done
        if issuer_cert.is_trusted:
            return PKICertificateStore.CERT_CA_SIGNED

        # Recursively validate the issuer certificate
        return issuer_store._walk_chain(issuer_cert)


# Basic implementation of RFC5246 (TLS 1.2 Protocol)
# https://tools.ietf.org/html/rfc5246
# https://tools.ietf.org/html/rfc5280
# https://tls.ulfheim.net/
# https://cryptography.io/en/latest/

# Version Identifier
PROTOCOL_VERSION = 0x0303

# TLS protocol record types
RECORD_CHANGE_CIPHER_SPEC = 0x14
RECORD_ALERT              = 0x15
RECORD_HANDSHAKE          = 0x16
RECORD_APPLICATION_DATA   = 0x17

# Handshake protocol record types
# See the TLS HandshakeType registry for a full list of allowed types
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7
HANDSHAKE_CLIENT_HELLO        = 0x01
HANDSHAKE_SERVER_HELLO        = 0x02
HANDSHAKE_CERTIFICATE         = 0x0b
HANDSHAKE_SERVER_KEY_EXCHANGE = 0x0c
HANDSHAKE_SERVER_HELLO_DONE   = 0x0e
HANDSHAKE_CLIENT_KEY_EXCHANGE = 0x10
HANDSHAKE_FINISHED            = 0x14
HANDSHAKE_CERTIFICATE_STATUS  = 0x16

# Extension types
# https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
EXTENSION_SERVER_NAME                            = 0x0000
EXTENSION_STATUS_REQUEST                         = 0x0005
EXTENSION_SUPPORTED_GROUPS                       = 0x000A
EXTENSION_EC_POINTS_FORMAT                       = 0x000B
EXTENSION_SIGNATURE_ALGORITHMS                   = 0x000D
EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010
EXTENSION_SIGNED_CERT_TIMESTAMP                  = 0x0012
EXTENSION_PADDING                                = 0x0015
EXTENSION_EXTENDED_MASTER_SECRET                 = 0x0017
EXTENSION_COMPRESS_CERTIFICATE                   = 0x001b
EXTENSION_SESSION_TICKET                         = 0x0023
EXTENSION_SUPPORTED_VERSIONS                     = 0x002b
EXTENSION_PSK_KEY_EXCHANGE_MODES                 = 0x002d
EXTENSION_KEY_SHARE                              = 0x0033
EXTENSION_RENEGOTIATION_INFO                     = 0xFF01

# Cipher suite definitions
# TLS_[Key Exchange]_WITH_[Cipher]_[MAC Hash Algorithm]
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xcca8
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xc02f
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xc030
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xc02b
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xc02c
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = 0xc013
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = 0xc009
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = 0xc014
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = 0xc00a
TLS_RSA_WITH_AES_128_GCM_SHA256               = 0x009c
TLS_RSA_WITH_AES_256_GCM_SHA384               = 0x009d
TLS_RSA_WITH_AES_128_CBC_SHA                  = 0x002f
TLS_RSA_WITH_AES_256_CBC_SHA                  = 0x0035
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = 0xc012
TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = 0x000a

# List of ciphers currently supported
supported_ciphers = [TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]

cipher_parameters = {
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:    (None, None, hashes.SHA256()),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:  (None, None, hashes.SHA256()),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:          (None, None, hashes.SHA256()),
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:          (None, None, hashes.SHA384()),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:        (None, None, hashes.SHA256()),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:        (None, None, hashes.SHA384()),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:             (None, None, hashes.SHA1()),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:           (None, None, hashes.SHA1()),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:             (None, None, hashes.SHA1()),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:           (None, None, hashes.SHA1()),
    TLS_RSA_WITH_AES_128_GCM_SHA256:                (None, None, hashes.SHA256()),
    TLS_RSA_WITH_AES_256_GCM_SHA384:                (None, None, hashes.SHA384()),
    TLS_RSA_WITH_AES_128_CBC_SHA:                   (None, None, hashes.SHA1()),
    TLS_RSA_WITH_AES_256_CBC_SHA:                   (None, None, hashes.SHA1()),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:            (None, None, hashes.SHA1()),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA:                  (None, None, hashes.SHA1())
}

# Curve definitions
CURVE_X25519    = 0x001d
CURVE_SECP256R1 = 0x0017
CURVE_SECP384R1 = 0x0018
CURVE_SECP521R1 = 0x0019

# List of curve types currently supported
supported_curves = [CURVE_X25519, CURVE_SECP256R1, CURVE_SECP384R1, CURVE_SECP521R1]

# Signature algorithm definitions
SIGNATURE_RSA_PKCS1_SHA256       = 0x0401
SIGNATURE_ECDSA_SECP256R1_SHA256 = 0x0403
SIGNATURE_RSA_PKCS1_SHA386       = 0x0501
SIGNATURE_ECDSA_SECP384R1_SHA384 = 0x0503
SIGNATURE_RSA_PKCS1_SHA512       = 0x0601
SIGNATURE_ECDSA_SECP521R1_SHA512 = 0x0603
SIGNATURE_RSA_PKCS1_SHA1         = 0x0201
SIGNATURE_ECDSA_SHA1             = 0x0203

# List of signature algorithms currently supported
supported_signatures = [SIGNATURE_RSA_PKCS1_SHA256, SIGNATURE_RSA_PKCS1_SHA386, SIGNATURE_RSA_PKCS1_SHA512]

# Encryption block padding
padding_bytes = {
    0x00: b"\x00",
    0x01: b"\x01\x01",
    0x02: b"\x02\x02\x02",
    0x03: b"\x03\x03\x03\x03",
    0x04: b"\x04\x04\x04\x04\x04",
    0x05: b"\x05\x05\x05\x05\x05\x05",
    0x06: b"\x06\x06\x06\x06\x06\x06\x06",
    0x07: b"\x07\x07\x07\x07\x07\x07\x07\x07",
    0x08: b"\x08\x08\x08\x08\x08\x08\x08\x08\x08",
    0x09: b"\x09\x09\x09\x09\x09\x09\x09\x09\x09\x09",
    0x0a: b"\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
    0x0b: b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
    0x0c: b"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
    0x0d: b"\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d",
    0x0e: b"\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e",
    0x0f: b"\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
}


class TLSSocket12:

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stream = None
        self.local_random = None
        self.remote_random = None
        self.cipher_suite = None
        self.mac_algorithm = None
        self.curve_id = None
        self.session_id = None
        self.remote_public_key = None
        self.local_write_key = None
        self.local_write_mac_key = None
        self.remote_write_key = None
        self.remote_write_mac_key = None
        self.read_sequence_id = 0
        self.write_sequence_id = 0
        self.certificate_validation = None
        self.certificate_store = PKICertificateStore(parent_store = PKICertificateStore.get_ca_store())
        self.all_handshake_hash = hashes.Hash(hashes.SHA256(), default_backend())

    def listen(self):
        # Load the server pem file and spit into constituents
        with open(CONFIGURATION["certificate_path"], "r") as f:
            data = f.read()
        parts = re.split('-----BEGIN', data)[1:]
        parts = [b'-----BEGIN' + part.encode("latin_1") for part in parts]

        # The first entry is expected to be the private key
        certificate_private_key_pem = parts[0]
        certificate_private_key = serialization.load_pem_private_key(certificate_private_key_pem, None, default_backend())

        # Load the certificates
        certificate_chain = []
        for pem in parts[1:]:
            certificate = PKICertificate()
            certificate.load_from_pem(pem)
            certificate_data = certificate.get_public_bytes()
            certificate_chain.append(certificate_data)

        # Listen for connection
        self.socket.bind(("127.0.0.1", 443))
        self.socket.listen(1)
        incoming_socket, address = self.socket.accept()
        self.stream = SocketStream(incoming_socket, SocketStream.BIG_ENDIAN)

        # Perform key exchange
        local_private_key = x25519.X25519PrivateKey.generate()
        self.__receive_client_hello()
        self.__send_server_hello()
        self.__send_certificates(certificate_chain)
        self.__send_server_key_exchange(local_private_key, certificate_private_key)
        self.__send_server_hello_done()
        self.stream.flush()
        self.__receive_client_key_exchange()
        self.__receive_change_cipher_spec()

        # Compute shared encryption keys
        pre_master_secret = local_private_key.exchange(self.remote_public_key)
        master_secret = self.__compute_master_secret(b"master secret" + self.remote_random + self.local_random, pre_master_secret)
        encryption_keys = self.__compute_key_expansion(b"key expansion" + self.local_random + self.remote_random, master_secret)
        self.remote_write_mac_key = encryption_keys[00:20]
        self.local_write_mac_key = encryption_keys[20:40]
        self.remote_write_key = encryption_keys[40:56]
        self.local_write_key = encryption_keys[56:72]

        # finish up
        self.__receive_finished(b"client finished" + self.all_handshake_hash.copy().finalize(), master_secret, True)
        self.__send_change_cipher_spec()
        self.__send_finished(b"server finished" + self.all_handshake_hash.finalize(), master_secret)
        self.stream.flush()

    def connect(self, address, validate_host):
        self.socket.connect(address)
        self.stream = SocketStream(self.socket, SocketStream.BIG_ENDIAN)

        # Perform key exchange
        self.__send_client_hello(address[0])
        self.stream.flush()
        self.__receive_server_hello()
        self.__receive_certificates()
        self.__receive_certificate_status()
        host = address[0] if validate_host else None
        self.certificate_validation = self.certificate_store.validate_chain(self.certificate_store.get_first_cert(), host)
        if self.certificate_validation == PKICertificateStore.CERT_INVALID:
            raise ValueError("Invalid certificate")
        self.__receive_server_key_exchange()
        self.__receive_server_hello_done()

        # Compute encryption keys
        if self.curve_id == CURVE_X25519:
            local_private_key = x25519.X25519PrivateKey.generate()
            local_public_key_data = local_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            pre_master_secret = local_private_key.exchange(self.remote_public_key)
        elif self.curve_id == CURVE_SECP256R1:
            local_private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
            local_public_key_data = local_private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            pre_master_secret = local_private_key.exchange(ec.ECDH(), self.remote_public_key)
        elif self.curve_id == CURVE_SECP384R1:
            local_private_key = ec.generate_private_key(ec.SECP384R1(), backend=default_backend())
            local_public_key_data = local_private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            pre_master_secret = local_private_key.exchange(ec.ECDH(), self.remote_public_key)
        elif self.curve_id == CURVE_SECP521R1:
            local_private_key = ec.generate_private_key(ec.SECP521R1(), backend=default_backend())
            local_public_key_data = local_private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            pre_master_secret = local_private_key.exchange(ec.ECDH(), self.remote_public_key)
        else:
            raise ValueError("Unsupported public key type")

        master_secret = self.__compute_master_secret(b"master secret" + self.local_random + self.remote_random, pre_master_secret)
        encryption_keys = self.__compute_key_expansion(b"key expansion" + self.remote_random + self.local_random, master_secret)
        self.local_write_mac_key = encryption_keys[00:20]
        self.remote_write_mac_key = encryption_keys[20:40]
        self.local_write_key = encryption_keys[40:56]
        self.remote_write_key = encryption_keys[56:72]

        # finish up
        self.__send_client_key_exchange(local_public_key_data)
        self.__send_change_cipher_spec()
        self.__send_finished(b"client finished" + self.all_handshake_hash.copy().finalize(), master_secret, True)
        self.stream.flush()
        self.__receive_change_cipher_spec()
        self.__receive_finished(b"server finished" + self.all_handshake_hash.finalize(), master_secret)

    def send(self, message):
        encrypt_iv, encrypted_data = self.__encrypt(message, b"\x17\x03\x03")
        self.stream.write_u8(RECORD_APPLICATION_DATA)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(len(encrypt_iv) + len(encrypted_data))
        self.stream.write_u8_array(encrypt_iv)
        self.stream.write_u8_array(encrypted_data)
        self.stream.flush()

    def recv(self):
        # Receive and decrypt the next application data packet
        record_type, record_length = self.__receive_record_header()
        if record_type != RECORD_APPLICATION_DATA:
            raise ValueError("Unexpected record type")
        if record_length < 32:          # Must be at least length of initialization vector plus one data block
            raise ValueError("Illegal record length")
        return self.__decrypt(record_length, b"\x17\x03\x03")

    def close(self):
        self.socket.close()

    def __compute_master_secret(self, seed, pre_master_secret):
        h = hmac.HMAC(pre_master_secret, hashes.SHA256(), default_backend())
        h.update(seed)
        a1 = h.finalize()
        h = hmac.HMAC(pre_master_secret, hashes.SHA256(), default_backend())
        h.update(a1)
        a2 = h.finalize()
        h = hmac.HMAC(pre_master_secret, hashes.SHA256(), default_backend())
        h.update(a1 + seed)
        p1 = h.finalize()
        h = hmac.HMAC(pre_master_secret, hashes.SHA256(), default_backend())
        h.update(a2 + seed)
        p2 = h.finalize()
        master_secret = p1 + p2[:16]
        return master_secret

    def __compute_key_expansion(self, seed, master_secret):
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(seed)
        a1 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a1)
        a2 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a2)
        a3 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a1 + seed)
        p1 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a2 + seed)
        p2 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a3 + seed)
        p3 = h.finalize()
        return p1 + p2 + p3

    def __compute_handshake_verification(self, verification_data, master_secret):
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(verification_data)
        a1 = h.finalize()
        h = hmac.HMAC(master_secret, hashes.SHA256(), default_backend())
        h.update(a1 + verification_data)
        p1 = h.finalize()
        return p1[:12]

    def __send_client_hello(self, host):
        len_host = len(host)
        len_ciphers = len(supported_ciphers) * 2
        len_signatures = len(supported_signatures) * 2
        len_curves = len(supported_curves) * 2
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(0x0301)                # Protocol version must be TLS V1.0 in client_hello record
        self.stream.write_u16(0x005a + len_ciphers + len_host + len_curves + len_signatures)  # record length

        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_CLIENT_HELLO)
        self.stream.write_u24(0x0056 + len_ciphers + len_host + len_curves + len_signatures)  # handshake record length
        self.stream.write_u16(PROTOCOL_VERSION)
        self.local_random = os.urandom(32)
        self.stream.write_u8_array(self.local_random)
        self.stream.write_u8(0x00)                   # Session ID length of 0 indicates that this is a new session
        self.stream.write_u16(len_ciphers)
        for cipher in supported_ciphers:
            self.stream.write_u16(cipher)
        self.stream.write_u16(0x0100)                # Compression is not supported
        self.stream.write_u16(0x002d + len_host + len_curves + len_signatures)   # Length of all extensions
        self.stream.write_u16(EXTENSION_SERVER_NAME)
        self.stream.write_u16(0x0005 + len_host)     # Extension length
        self.stream.write_u16(0x0003 + len_host)     # Length of first name
        self.stream.write_u8(0x00)                   # Name type = DNS Hostname
        self.stream.write_u16(len_host)              # Host name length
        self.stream.write_string(host)                 # Host name
        self.stream.write_u16(EXTENSION_STATUS_REQUEST)
        self.stream.write_u16(0x0005)                # Extension length
        self.stream.write_u8(0x01)                   # Certificate status type: OCSP
        self.stream.write_u16(0x0000)                # 0 bytes of responder ID information
        self.stream.write_u16(0x0000)                # 0 bytes of request extension information
        self.stream.write_u16(EXTENSION_SUPPORTED_GROUPS)
        self.stream.write_u16(len_curves + 2)        # Extension length
        self.stream.write_u16(len_curves)            # Length of curve groups data
        for curve_id in supported_curves:
            self.stream.write_u16(curve_id)
        self.stream.write_u16(EXTENSION_EC_POINTS_FORMAT)
        self.stream.write_u16(0x0002)                # Extension length
        self.stream.write_u8(0x01)                   # Length of formats list
        self.stream.write_u8(0x00)                   # Format = Uncompressed
        self.stream.write_u16(EXTENSION_SIGNATURE_ALGORITHMS)
        self.stream.write_u16(len_signatures + 2)    # Extension length
        self.stream.write_u16(len_signatures)        # Length of signature algorithms data
        for signature in supported_signatures:
            self.stream.write_u16(signature)
        self.stream.write_u16(EXTENSION_RENEGOTIATION_INFO)
        self.stream.write_u16(0x0001)                # Extension length
        self.stream.write_u8(0x00)                   # Renegotiation info length of 0 indicates a new connection
        self.stream.write_u16(EXTENSION_SIGNED_CERT_TIMESTAMP)
        self.stream.write_u16(0x0000)                # Extension length
        self.all_handshake_hash.update(self.stream.get_write_buffer()[record_start:])

    def __send_server_hello(self):
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(0x002c)                 # length of record
        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_SERVER_HELLO)
        self.stream.write_u24(0x0028)                 # length of handshake record
        self.stream.write_u16(PROTOCOL_VERSION)
        self.local_random = os.urandom(32)
        self.stream.write_u8_array(self.local_random)
        self.stream.write_u8(0)                       # length of session ID
        self.stream.write_u16(TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)     # Cipher suite
        self.mac_algorithm = hashes.SHA1()              # algorithm for TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        self.stream.write_u8(0)                       # no compression
        self.stream.write_u16(0x0000)                 # length of all extensions
        record_data = self.stream.get_write_buffer()[record_start:]
        self.all_handshake_hash.update(record_data)

    def __send_certificates(self, certificates):

        # Calculate combined length of all certificates
        len_all_certs = 0
        for cert in certificates:
            len_all_certs += len(cert)
        num_certificates = len(certificates)

        # Send all certificates
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(len_all_certs + (num_certificates*3) + 7)   # length of record
        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_CERTIFICATE)
        self.stream.write_u24(len_all_certs + (num_certificates*3) + 3)   # length of handshake record
        self.stream.write_u24(len_all_certs + (num_certificates*3))       # length of all certificates
        for cert in certificates:
            self.stream.write_u24(len(cert))                              # length of certificate data
            self.stream.write_u8_array(cert)                                   # certificate data
        record_data = self.stream.get_write_buffer()[record_start:]
        self.all_handshake_hash.update(record_data)

    def __send_server_key_exchange(self, local_private_key, certificate_private_key):
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(0x012c)                         # length of record
        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_SERVER_KEY_EXCHANGE)
        self.stream.write_u24(0x0128)                         # length of handshake record
        record = ByteStream(ByteStream.BIG_ENDIAN)
        record.write_u8(3)                                    # curve type
        record.write_u16(CURVE_X25519)                        # curve id
        local_public_key_data = local_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        record.write_u8(len(local_public_key_data))           # pub key length
        record.write_u8_array(local_public_key_data)               # pub key bytes
        message_to_sign = bytes(self.remote_random + self.local_random + record.get_data())
        signature = certificate_private_key.sign(message_to_sign, padding.PKCS1v15(), hashes.SHA256())
        self.stream.write_u8_array(record.get_data())
        self.stream.write_u16(SIGNATURE_RSA_PKCS1_SHA256)      # signature type
        self.stream.write_u16(len(signature))                  # signature length
        self.stream.write_u8_array(signature)                       # signature
        record_data = self.stream.get_write_buffer()[record_start:]
        self.all_handshake_hash.update(record_data)

    def __send_server_hello_done(self):
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(0x0004)                     # length of record
        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_SERVER_HELLO_DONE)
        self.stream.write_u24(0x000000)                   # length of handshake record
        record_data = self.stream.get_write_buffer()[record_start:]
        self.all_handshake_hash.update(record_data)

    def __send_client_key_exchange(self, key_data):
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(len(key_data) + 5)
        record_start = self.stream.get_length()
        self.stream.write_u8(HANDSHAKE_CLIENT_KEY_EXCHANGE)
        self.stream.write_u24(len(key_data) + 1)
        self.stream.write_u8(len(key_data))
        self.stream.write_u8_array(key_data)
        self.all_handshake_hash.update(self.stream.get_write_buffer()[record_start:])

    def __send_change_cipher_spec(self):
        self.stream.write_u8(RECORD_CHANGE_CIPHER_SPEC)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(0x001)
        self.stream.write_u8(0x01)

    def __send_finished(self, verification_data, master_secret, add_to_hash=False):
        # Calculate verification of all handshake packets
        verification_hash = self.__compute_handshake_verification(verification_data, master_secret)

        # Generate a Finished record
        to_encrypt = ByteStream(ByteStream.BIG_ENDIAN)
        to_encrypt.write_u8(HANDSHAKE_FINISHED)
        to_encrypt.write_u24(len(verification_hash))
        to_encrypt.write_u8_array(verification_hash)

        # Add to handshake hash
        if add_to_hash:
            self.all_handshake_hash.update(to_encrypt.get_data())

        # Encrypt the record
        encrypt_iv, encrypted_data = self.__encrypt(to_encrypt.get_data(), b"\x16\x03\x03")

        # Send the record
        self.stream.write_u8(RECORD_HANDSHAKE)
        self.stream.write_u16(PROTOCOL_VERSION)
        self.stream.write_u16(len(encrypt_iv) + len(encrypted_data))
        self.stream.write_u8_array(encrypt_iv)
        self.stream.write_u8_array(encrypted_data)

    def __receive_record_header(self, expected_protocol_version=None):
        record_type = self.stream.read_u8()
        protocol_version = self.stream.read_u16()
        expected_protocol_version = expected_protocol_version if expected_protocol_version is not None else PROTOCOL_VERSION
        if protocol_version != expected_protocol_version:
            raise ValueError("Illegal protocol version")
        record_length = self.stream.read_u16()
        if record_type == RECORD_ALERT:
            alert_level = self.stream.read_u8()
            alert_description = self.stream.read_u8()
            self.stream.close()
            raise ValueError("Alert " + str(alert_level) + "," + str(alert_description) )
        return record_type, record_length

    def __receive_handshake_record(self, expected_protocol=None):
        record_type, record_length = self.__receive_record_header(expected_protocol)
        if record_type != RECORD_HANDSHAKE:
            raise ValueError("Unexpected record type")
        record_data = self.stream.read_u8_array(record_length)
        self.all_handshake_hash.update(record_data)
        record = ByteStream(ByteStream.BIG_ENDIAN)
        record.set_data(record_data)
        handshake_type = record.read_u8()
        handshake_length = record.read_u24()
        return record, handshake_type, handshake_length

    def __receive_client_hello(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record(0x0301)
        if handshake_type != HANDSHAKE_CLIENT_HELLO:
            raise ValueError("Unexpected handshake record")
        client_protocol_version = handshake_record.read_u16()
        if client_protocol_version != PROTOCOL_VERSION:
            raise ValueError("Unsupported protocol version")
        self.remote_random = handshake_record.read_u8_array(32)
        session_id_length = handshake_record.read_u8()
        self.session_id = handshake_record.read_u8_array(session_id_length)
        num_ciphers = handshake_record.read_u16() // 2
        client_supported_ciphers = []
        for i in range(num_ciphers):
            client_supported_ciphers.append(handshake_record.read_u16())
        if TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA not in client_supported_ciphers:
            raise ValueError("Cipher suites unsupported")
        compression = handshake_record.read_u16()
        if compression != 0x0100:
            raise ValueError("Compression not supported")
        len_extensions = handshake_record.read_u16()
        while len_extensions > 0:
            extension_type = handshake_record.read_u16()
            extension_length = handshake_record.read_u16()
            if extension_type == EXTENSION_STATUS_REQUEST:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SUPPORTED_GROUPS:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_EC_POINTS_FORMAT:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SIGNATURE_ALGORITHMS:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SIGNED_CERT_TIMESTAMP:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_PADDING:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_EXTENDED_MASTER_SECRET:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_COMPRESS_CERTIFICATE:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SESSION_TICKET:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SUPPORTED_VERSIONS:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_PSK_KEY_EXCHANGE_MODES:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_KEY_SHARE:
                extension_data = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_RENEGOTIATION_INFO:
                extension_data = handshake_record.read_u8_array(extension_length)
            else:
                extension_data = handshake_record.read_u8_array(extension_length)
            len_extensions -= extension_length + 4

    def __receive_server_hello(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record()
        if handshake_type != HANDSHAKE_SERVER_HELLO:
            raise ValueError("Unexpected handshake record")
        server_protocol_version = handshake_record.read_u16()
        if server_protocol_version != PROTOCOL_VERSION:
            raise ValueError("Unexpected server protocol version")
        self.remote_random = handshake_record.read_u8_array(32)
        session_id_length = handshake_record.read_u8()
        if session_id_length > 32:
            raise ValueError("Illegal Session ID length")
        self.session_id = handshake_record.read_u8_array(session_id_length)
        self.cipher_suite = handshake_record.read_u16()
        if self.cipher_suite not in supported_ciphers:
            raise ValueError("Unsupported cipher")
        self.mac_algorithm = cipher_parameters[self.cipher_suite][2]
        compression_method = handshake_record.read_u8()
        if compression_method != 0:
            raise ValueError("Unsupported compression method")
        extensions_length = handshake_record.read_u16()
        if extensions_length > 4096:       # Arbitrary safe limit
            raise ValueError("Illegal extensions length")
        while extensions_length > 0:
            extension_type = handshake_record.read_u16()
            extension_length = handshake_record.read_u16()
            if extension_length > 2048:     # Arbitrary safe limit
                raise ValueError("Illegal extension length")
            if extension_type == EXTENSION_SERVER_NAME:
                server_name = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_STATUS_REQUEST:
                status_request = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_EC_POINTS_FORMAT:
                ec_points_format = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_SIGNED_CERT_TIMESTAMP:
                signed_cert_timestamp = handshake_record.read_u8_array(extension_length)
            elif extension_type == EXTENSION_RENEGOTIATION_INFO:
                renegotiation_info = handshake_record.read_u8_array(extension_length)
            else:
                raise ValueError("Unknown extension type")
            extensions_length -= extension_length + 4

    def __receive_certificates(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record()
        if handshake_type != HANDSHAKE_CERTIFICATE:
            raise ValueError("Unexpected handshake record")
        certificates_length = handshake_record.read_u24()
        if certificates_length > 16384:       # Arbitrary safe limit
            raise ValueError("Illegal certificates length")
        while certificates_length:
            certificate_length = handshake_record.read_u24()
            certificate_der = handshake_record.read_u8_array(certificate_length)
            certificate = PKICertificate()
            certificate.load_from_der(certificate_der)
            self.certificate_store.add(certificate)
            certificates_length -= certificate_length + 3

    def __receive_certificate_status(self):
        # The certificate status record is optional in the response from the server
        record_type, record_length = self.__receive_record_header()
        if record_type != RECORD_HANDSHAKE:
            raise ValueError("Unexpected record type")
        record_data = self.stream.read_u8_array(record_length)
        handshake_record = ByteStream(ByteStream.BIG_ENDIAN)
        handshake_record.set_data(record_data)
        handshake_type = handshake_record.read_u8()
        handshake_length = handshake_record.read_u24()
        if handshake_type == HANDSHAKE_CERTIFICATE_STATUS:
            self.all_handshake_hash.update(record_data)
            # Currently don't do anything with the OSCP response
            ocsp_response = handshake_record.read_u8_array(handshake_length)
        else:
            # This is not the record we're looking for, so rewind a little bit
            self.stream.set_position(-handshake_length-9, io.SEEK_CUR)

    def __receive_server_key_exchange(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record()
        if handshake_type != HANDSHAKE_SERVER_KEY_EXCHANGE:
            raise ValueError("Unexpected handshake record")
        message_start = handshake_record.get_position()
        curve_type = handshake_record.read_u8()
        if curve_type != 3:     # Only named curves are supported
            raise ValueError("Unsupported curve type")
        self.curve_id = handshake_record.read_u16()
        if self.curve_id not in supported_curves:
            raise ValueError("Unsupported curve")
        remote_public_key_length = handshake_record.read_u8()
        remote_public_key_data = handshake_record.read_u8_array(remote_public_key_length)
        message_to_verify = bytes(self.local_random + self.remote_random + handshake_record.get_data()[message_start:handshake_record.get_position()])

        # Verify the provided server public key by ensuring it was signed with the server certificate
        signature_id = handshake_record.read_u16()
        if signature_id not in supported_signatures:
            raise ValueError("Unsupported signature algorithm")
        signature_length = handshake_record.read_u16()
        if signature_length > 256:
            raise ValueError("Illegal signature length")
        signature = bytes(handshake_record.read_u8_array(signature_length))

        hash_type = signature_id >> 8
        if hash_type == 2:
            hash_object = hashes.SHA1()
        elif hash_type == 4:
            hash_object = hashes.SHA256()
        elif hash_type == 5:
            hash_object = hashes.SHA384()
        elif hash_type == 6:
            hash_object = hashes.SHA512()
        else:
            raise ValueError("Illegal hash definition")

        cert_public_key = self.certificate_store.get_first_cert().get_public_key()
        try:
            cert_public_key.verify(signature, message_to_verify, padding.PKCS1v15(), hash_object)
        except exceptions.InvalidSignature:
            raise ValueError("Invalid server public key")

        # Import server public key
        if self.curve_id == CURVE_X25519:
            self.remote_public_key = x25519.X25519PublicKey.from_public_bytes(bytes(remote_public_key_data))
        elif self.curve_id == CURVE_SECP256R1:
            self.remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes(remote_public_key_data))
        elif self.curve_id == CURVE_SECP384R1:
            self.remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), bytes(remote_public_key_data))
        elif self.curve_id == CURVE_SECP521R1:
            self.remote_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), bytes(remote_public_key_data))
        else:
            raise ValueError("Unsupported public key type")

    def __receive_server_hello_done(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record()
        if handshake_type != HANDSHAKE_SERVER_HELLO_DONE:
            raise ValueError("Unexpected handshake record")

    def __receive_client_key_exchange(self):
        handshake_record, handshake_type, handshake_length = self.__receive_handshake_record()
        if handshake_type != HANDSHAKE_CLIENT_KEY_EXCHANGE:
            raise ValueError("Unexpected handshake type")
        key_length = handshake_record.read_u8()
        key_data = handshake_record.read_u8_array(key_length)
        self.remote_public_key = x25519.X25519PublicKey.from_public_bytes(bytes(key_data))

    def __receive_change_cipher_spec(self):
        record_type, record_length = self.__receive_record_header()
        if record_type != RECORD_CHANGE_CIPHER_SPEC:
            raise("Unexpected record type")
        if record_length != 1:
            raise ValueError("Illegal cipher spec length")
        cipher_spec = self.stream.read_u8()
        if cipher_spec != 0x01:
            raise ValueError("Illegal cipher spec")

    def __receive_finished(self, verification_data, master_secret, add_to_hash=False):
        record_type, record_length = self.__receive_record_header()
        if record_type != RECORD_HANDSHAKE:
            raise("Unexpected record type")

        # Decrypt the finished record
        message = self.__decrypt(record_length, b"\x16\x03\x03")
        decrypted = ByteStream(ByteStream.BIG_ENDIAN)
        decrypted.set_data(message)

        # Get the verification hash from the decrypted record
        handshake_type = decrypted.read_u8()
        if handshake_type != HANDSHAKE_FINISHED:
            raise ValueError("Unexpected handshake packet")
        handshake_length = decrypted.read_u24()
        if handshake_length != 0x0c:
            raise ValueError("Illegal verification length")
        verification_hash = decrypted.read_u8_array(handshake_length)

        # Compute verification hash and compare to the received hash
        computed_hash = self.__compute_handshake_verification(verification_data, master_secret)
        if computed_hash != verification_hash:
            raise ValueError("Verification failed")

        # Add decrypted record to handshake hash
        if add_to_hash:
            self.all_handshake_hash.update(message)

    def __encrypt(self, message, header):
        # Generate a Message Authentication Code for this data
        mac_input = struct.pack(">Q", self.write_sequence_id) + header + struct.pack(">H", len(message)) + message
        h = hmac.HMAC(self.local_write_mac_key, self.mac_algorithm, default_backend())
        h.update(mac_input)
        mac = h.finalize()
        self.write_sequence_id += 1

        # Calculate length of padding needed to round block size up to multiple of encryption block size
        block_size = 16
        block_padding = padding_bytes[block_size - ((len(message) + self.mac_algorithm.digest_size + 1) & (block_size-1))]

        # Encrypt the data
        encrypt_iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(self.local_write_key), modes.CBC(encrypt_iv), backend=default_backend()).encryptor()
        encrypted_data = encryptor.update(message + mac + block_padding) + encryptor.finalize()
        return encrypt_iv, encrypted_data

    def __decrypt(self, block_length, header):
        # Decrypt the data
        encrypt_iv = self.stream.read_u8_array(16)
        encrypted_data = self.stream.read_u8_array(block_length - 16)
        decryptor = Cipher(algorithms.AES(self.remote_write_key), modes.CBC(encrypt_iv), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Extract the message and MAC
        len_padding = struct.unpack("B", decrypted_data[-1:])[0] + 1      # includes padding length byte
        len_mac_and_padding = self.mac_algorithm.digest_size + len_padding
        message = decrypted_data[:-len_mac_and_padding]
        mac = decrypted_data[-len_mac_and_padding:-len_padding]

        # Verify the Message Authentication Code
        expected_mac_input = struct.pack(">Q", self.read_sequence_id) + header + struct.pack(">H", len(message)) + message
        h = hmac.HMAC(self.remote_write_mac_key, self.mac_algorithm, default_backend())
        h.update(expected_mac_input)
        expected_mac = h.finalize()
        self.read_sequence_id += 1
        if expected_mac != mac:
            raise ValueError("MAC verification failed")

        # All good, return the decrypted data
        return message


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.exit(PURPOSE)

    if sys.version_info < (3, 6):
        sys.exit("Requires Python 3.6 or later")

    mode = sys.argv[1]
    if mode == "client":
        validate_host = True
        for site in CONFIGURATION["test_sites"]:
            s = TLSSocket12()
            s.connect((site, 443), validate_host)
            s.send(b"GET / HTTP/1.1\r\n\r\n")
            data = s.recv()
            if s.certificate_validation == PKICertificateStore.CERT_INVALID:
                print (site + " failed (certificate invalid)")
            elif s.certificate_validation == PKICertificateStore.CERT_SELF_SIGNED:
                print (site + " succeeded (self-signed)")
            elif s.certificate_validation == PKICertificateStore.CERT_CA_SIGNED:
                print (site + " succeeded (CA signed)")

    elif mode == "server":
        s = TLSSocket12()
        s.listen()
        data = s.recv()
        print (data)
        s.send(b"Success!")
