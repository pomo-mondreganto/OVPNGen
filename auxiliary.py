NUM_LEN = 3


def format_number(num):
    return str(num).zfill(NUM_LEN)


def strip_zeros(formatted_num):
    return formatted_num.lstrip('0').zfill(1)
