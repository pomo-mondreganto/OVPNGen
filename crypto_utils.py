from OpenSSL import crypto
import subprocess


def make_key_pair(algorithm=crypto.TYPE_RSA, num_bits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, num_bits)
    return pkey


def make_csr(pkey, CN, email=None, hash_algorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    subj = req.get_subject()

    subj.CN = CN

    if email:
        subj.emailAddress = email

    req.set_pubkey(pkey)
    # noinspection PyTypeChecker
    req.sign(pkey, hash_algorithm)
    return req


def create_ca(CN, hash_algorithm='sha256WithRSAEncryption', *args):
    ca_key = make_key_pair()
    ca_req = make_csr(ca_key, CN=CN, *args)
    ca_cert = crypto.X509()
    ca_cert.set_serial_number(0)
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 10)  # 10 years
    ca_cert.set_issuer(ca_req.get_subject())
    ca_cert.set_subject(ca_req.get_subject())
    ca_cert.set_pubkey(ca_req.get_pubkey())
    ca_cert.set_version(2)

    ca_cert.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca_cert)
    ])

    ca_cert.add_extensions([
        crypto.X509Extension(
            b'authorityKeyIdentifier',
            False, b'issuer:always, keyid:always',
            issuer=ca_cert,
            subject=ca_cert,
        )
    ])

    # noinspection PyTypeChecker
    ca_cert.sign(ca_key, hash_algorithm)
    return ca_cert, ca_key


def create_slave_certificate(csr, ca_key, ca_cert, serial, hash_algorithm='sha256WithRSAEncryption'):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60 * 60 * 24 * 365 * 10)  # 10 years
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = [
        crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
        crypto.X509Extension(
            b'authorityKeyIdentifier',
            False, b'keyid:always,issuer:always',
            subject=ca_cert,
            issuer=ca_cert,
        ),
    ]

    cert.add_extensions(extensions)
    # noinspection PyTypeChecker
    cert.sign(ca_key, hash_algorithm)

    return cert


def dump_file_in_mem(material, file_format=crypto.FILETYPE_PEM):
    if isinstance(material, crypto.X509):
        dump_func = crypto.dump_certificate
    elif isinstance(material, crypto.PKey):
        dump_func = crypto.dump_privatekey
    elif isinstance(material, crypto.X509Req):
        dump_func = crypto.dump_certificate_request
    else:
        raise Exception(f"Invalid file_format: {type(material)} {material}")

    return dump_func(file_format, material)


def load_file(path, obj_type, file_format=crypto.FILETYPE_PEM):
    if obj_type is crypto.X509:
        load_func = crypto.load_certificate
    elif obj_type is crypto.X509Req:
        load_func = crypto.load_certificate_request
    elif obj_type is crypto.PKey:
        load_func = crypto.load_privatekey
    else:
        raise Exception(f"Unsupported material type: {obj_type}")

    with open(path, 'r') as fp:
        buf = fp.read()

    material = load_func(file_format, buf)
    return material


def load_key_file(path):
    return load_file(path, crypto.PKey)


def load_csr_file(path):
    return load_file(path, crypto.X509Req)


def load_cert_file(path):
    return load_file(path, crypto.X509)


def start_dhparams_gen(dump_file):
    p = subprocess.Popen(['openssl', 'dhparam', '2048'], stderr=subprocess.PIPE, stdout=dump_file)
    return p


def dump_ovpn(common, key, cert, ca_cert, path):
    client_key = dump_file_in_mem(key).decode()
    client_cert = dump_file_in_mem(cert).decode()
    ca_cert_dump = dump_file_in_mem(ca_cert).decode()

    ovpn = (
        f"{common}\n"
        f"<ca>\n{ca_cert_dump}</ca>\n"
        f"<cert>\n{client_cert}</cert>\n"
        f"<key>\n{client_key}</key>\n"
    )

    with open(path, 'w') as f:
        f.write(ovpn)


def dump_object(obj, path):
    with open(path, 'w') as f:
        f.write(dump_file_in_mem(obj).decode())


def generate_server_conf(
        ca_cert_filename,
        ca_cert_path,
        ca_key_path,
        dh_param_filename,
        server_cert_filename,
        server_cert_path,
        server_key_filename,
        server_key_path,
        server_num,
        port_prefix,
        iface_prefix,
        serial,
        net,
        common_config_filename,
        out_path,
        mask):
    with open(common_config_filename, 'r') as f:
        common = f.read()

    server_name = f'{iface_prefix}_server_{server_num}'
    port = f'{port_prefix}{server_num}'
    iface = f'{iface_prefix}{server_num.lstrip("0")}'

    common = common.format(
        iface=iface,
        port=port,
        ca_cert_filename=ca_cert_filename,
        server_cert_filename=server_cert_filename,
        server_key_filename=server_key_filename,
        dh_param_filename=dh_param_filename,
        net=net,
        server_num=server_num.lstrip('0'),
        mask=mask,
    )

    ca_cert = load_cert_file(ca_cert_path)
    ca_key = load_key_file(ca_key_path)

    key = make_key_pair()
    csr = make_csr(key, server_name)
    cert = create_slave_certificate(csr, ca_key, ca_cert, serial)

    dump_object(key, server_key_path)
    dump_object(cert, server_cert_path)

    with open(out_path, 'w') as f:
        f.write(common)


def generate_client_ovpn(
        ca_cert_path,
        ca_key_path,
        client_num,
        server_host,
        serial,
        common_config_filename,
        client_type,
        port_prefix,
        out_path):
    with open(common_config_filename, 'r') as f:
        common = f.read()

    client_name = f'{client_type}{client_num}'
    server_port = f'{port_prefix}{client_num}'
    common = common.format(server_host=server_host, server_port=server_port)

    ca_cert = load_cert_file(ca_cert_path)
    ca_key = load_key_file(ca_key_path)

    key = make_key_pair()
    csr = make_csr(key, client_name)
    cert = create_slave_certificate(csr, ca_key, ca_cert, serial)

    dump_ovpn(common, key, cert, ca_cert, out_path)
