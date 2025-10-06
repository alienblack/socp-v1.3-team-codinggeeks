def encode_file_for_transfer(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
    return content.hex()

def decode_and_save_file(hex_str, dest_path):
    with open(dest_path, "wb") as f:
        f.write(bytes.fromhex(hex_str))
