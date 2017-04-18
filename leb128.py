def decode_leb128(data, sign, max_len):
    result = 0
    num_read = 0
    shift = 0
    byte = 0

    while num_read < max_len:
        byte = ord(data[num_read])
        num_read = num_read + 1

        result = result | ((byte & 0x7F) << shift)
        shift = shift + 7

        if (byte & 0x80) == 0:
            break

    #Python has always enough space for any large number
    if (sign and (byte & 0x40)):
        result = result | (-(1 << shift))
    return result, num_read
    

def decode_uleb128(data, max_len):
    return decode_leb128(data, False, max_len)

def decode_sleb128(data, max_len):
    return decode_leb128(data, True, max_len)

def main():
    testcase1 = '\x80\x01'
    testcase2 = '\xa0\x23'
    testcase3 = '\xb8\xff\xff\xff\xff\xff\xff\xff\xff\x01'
    testcase4 = '\xdc\xff\xff\xff\xff\xff\xff\xff\xff\x01'
    testcase5 = '\x9B\xF1\x59'
    testset = (testcase1, testcase2, testcase3, testcase4)
    for testcase in testset:
        result, num_read = decode_uleb128(testcase, len(testcase))
        if result & 0x8000000000000000:
            result = - ((result - 1) ^ 0xffffffffffffffff)
            
        print '{:d}'.format(result)
        print num_read

    result, num_read = decode_sleb128(testcase5, len(testcase5))
    print result
    print num_read
if __name__ == '__main__':
    main()