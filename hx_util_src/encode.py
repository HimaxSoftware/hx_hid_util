# 使用方式：xor_file.py <輸入檔> <輸出檔> <金鑰字串>
import sys
import lz4.block

input_file, output_file, key_file = sys.argv[1], sys.argv[2], sys.argv[3]
with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out, open(key_file, 'rb') as f_key:
    uncompressed_data = f_in.read()
    compressed_data = lz4.block.compress(uncompressed_data, store_size=False)
    key_data = f_key.read()
    key_len = len(key_data)
    xor_data = bytearray([compressed_data[i] ^ key_data[i % key_len] for i in range(len(compressed_data))])
    f_out.write(xor_data)
