import subprocess

from OpenSSL import crypto

from .auxiliary import strip_zeros


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


def create_slave_certificate(csr, ca_key, ca_cert, serial, is_server=False, hash_algorithm='sha256WithRSAEncryption'):
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

    if is_server:
        extensions.extend([
            crypto.X509Extension(b'keyUsage', False, b'digitalSignature,keyEncipherment'),
            crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'),
        ])

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


def generate_static_key():
    p = subprocess.Popen(
        ['openvpn', '--genkey', '--secret', '/dev/stdout'],
        stdout=subprocess.PIPE,
    )
    stdout, _ = p.communicate()
    return stdout.decode().strip('\n')


def dump_object(obj, path):
    with open(path, 'w') as f:
        f.write(dump_file_in_mem(obj).decode())


def generate_subnet_server_conf(
        static_key,
        ca_cert_filename,
        ca_cert_path,
        ca_key_path,
        dh_param_filename,
        server_cert_filename,
        server_key_filename,
        server_num,
        name_template,
        port_template,
        iface_template,
        serial,
        net,
        common_config_path,
        out_path_template,
        mask):
    with open(common_config_path, 'r') as f:
        common = f.read()

    server_name = name_template.format(num=server_num)
    port = port_template.format(num=server_num)
    iface = iface_template.format(num=strip_zeros(server_num))

    ca_cert = load_cert_file(ca_cert_path)
    ca_key = load_key_file(ca_key_path)

    key = make_key_pair()
    csr = make_csr(key, server_name)
    cert = create_slave_certificate(csr, ca_key, ca_cert, serial, is_server=True)

    dumped_key = dump_file_in_mem(key).decode().strip('\n')
    dumped_cert = dump_file_in_mem(cert).decode().strip('\n')

    common = common.format(
        iface=iface,
        port=port,
        ca_cert_filename=ca_cert_filename,
        server_cert_filename=server_cert_filename,
        server_key_filename=server_key_filename,
        dh_param_filename=dh_param_filename,
        net=net,
        server_num=strip_zeros(server_num),
        mask=mask,
        cert=dumped_cert,
        key=dumped_key,
        tls_auth=static_key,
    )

    out_path = out_path_template.format(num=server_num)
    with open(out_path, 'w') as f:
        f.write(common)


def generate_p2p_server_conf(
        static_key,
        common_config_path,
        iface_template,
        port_template,
        net,
        server_num,
        out_path_template):
    with open(common_config_path, 'r') as f:
        common = f.read()

    port = port_template.format(num=server_num)
    iface = iface_template.format(num=strip_zeros(server_num))

    common = common.format(
        iface=iface,
        port=port,
        net=net,
        server_num=strip_zeros(server_num),
        static_key=static_key,
    )

    out_path = out_path_template.format(num=server_num)
    with open(out_path, 'w') as f:
        f.write(common)


def generate_subnet_client_ovpn(
        static_key,
        ca_cert_path,
        ca_key_path,
        client_num,
        client_name,
        server_host,
        serial,
        common_config_filename,
        server_port_template,
        out_path):
    with open(common_config_filename, 'r') as f:
        common = f.read()

    server_port = server_port_template.format(num=client_num)

    ca_cert = load_cert_file(ca_cert_path)
    ca_key = load_key_file(ca_key_path)

    key = make_key_pair()
    csr = make_csr(key, client_name)
    cert = create_slave_certificate(csr, ca_key, ca_cert, serial)

    ca_cert_dump = dump_file_in_mem(ca_cert).decode().strip('\n')
    client_cert = dump_file_in_mem(cert).decode().strip('\n')
    client_key = dump_file_in_mem(key).decode().strip('\n')

    common = common.format(
        server_host=server_host,
        server_port=server_port,
        ca_cert_dump=ca_cert_dump,
        client_cert=client_cert,
        client_key=client_key,
        tls_auth=static_key,
    )

    with open(out_path, 'w') as f:
        f.write(common)


def generate_p2p_client_ovpn(
        static_key,
        client_num,
        server_host,
        common_config_filename,
        server_port_template,
        net,
        out_path):
    with open(common_config_filename, 'r') as f:
        common = f.read()

    server_port = server_port_template.format(num=client_num)
    common = common.format(
        server_host=server_host,
        server_port=server_port,
        net=net,
        client_num=strip_zeros(client_num),
        static_key=static_key,
    )

    with open(out_path, 'w') as f:
        f.write(common)
