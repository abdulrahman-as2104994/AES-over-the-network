import json
import math
import time
import clipboard
import tabulate as tb

aes_sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

sbox_table = []
for i in range(16):
    sbox_table.append([])
    for j in range(16):
        sbox_table[i].append(hex(aes_sbox[i*16+j]))

inverse_aes_sbox = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

inverse_aes_sbox_table = []
for i in range(16):
    inverse_aes_sbox_table.append([])
    for j in range(16):
        inverse_aes_sbox_table[i].append(hex(inverse_aes_sbox[i*16+j]))

# Each list is a column, 10 columns for 10 rounds
round_constants = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1B, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00],
]

 # Each list is a row
standard_matrix = [
    ['0x02', '0x03', '0x01', '0x01'],
    ['0x01', '0x02', '0x03', '0x01'],
    ['0x01', '0x01', '0x02', '0x03'],
    ['0x03', '0x01', '0x01', '0x02']
]

 # Each list is a row
inverse_standard_matrix = [
    ['0x0E', '0x0B', '0x0D', '0x09'],
    ['0x09', '0x0E', '0x0B', '0x0D'],
    ['0x0D', '0x09', '0x0E', '0x0B'],
    ['0x0B', '0x0D', '0x09', '0x0E']
]

def print_short_line():
    print("-----------------------------------------------------")

def print_long_line():
    print("-------------------------------------------------------------------------------------------------------------")

def print_main_header():
    print("\n------------------------------------128-bit AES Encryption and Decryption------------------------------------")

def byte(x, n=8):
        return format(x, f"0{n}b")

def gf_2_8_product(a, b):
    tmp = 0
    b_byte = bin(b)[2:]
    for i in range(len(b_byte)):
        tmp = tmp ^ (int(b_byte[-(i+1)]) * (a << i))

    mod = int("100011011", 2)
    exp = len(bin(tmp)[2:])
    diff =  exp - len(bin(mod)[2:]) + 1

    for i in range(diff):
        if byte(tmp, exp)[i] == "1":
            tmp = tmp ^ (mod << diff - i - 1)
    return tmp

def check_to_pad(plainText):
    if len(plainText) % 16 != 0:
        return True
    else:
        try:
            zero_count = int(plainText[-1], 16)
            print("Added zeros should be:", zero_count)
        except ValueError:
            return False
        else:
            count = 0
            for char in range(zero_count):
                if plainText[-(char+2)] == "0":
                    count += 1
                else:
                    break
            print("Actual zeros:", count)
            if count == zero_count:
                return True
    return False

def padding(msg):
    padding_length = (16 - (len(msg) % 16))
    print("Padding...")
    print("Padding length:", padding_length)
    msg += ("0" * (padding_length - 1)) + hex(padding_length - 1)[2:]
    print("Padded plain text:", msg)
    return msg

def removePadding(msg):
    # Need to check if padding has been done
    try:
        padding_length = int(msg[-1], 16) + 1
    except ValueError:
        print("No padding found")
        return msg

    # Count the number of padding characters
    count = 0
    for char in range(padding_length - 1):
        if msg[-(char+2)] == "0":
            count += 1
        else:
            break
    if count == (padding_length - 1):
        print("Padding length:", padding_length)
        while padding_length > 0:
            msg = msg[:-1]
            padding_length -= 1
    return msg

def convert_to_128_bit(hex_list):
    # Ensure each hex value is 8 bits
    for i in range(len(hex_list)):
        # Convert hex to binary
        bin_val = bin(int(hex_list[i], 16))[2:]
        
        # If binary value is more than 8 bits, truncate it
        if len(bin_val) > 8:
            bin_val = bin_val[:8]
        
        # Convert binary back to hex and update the list
        hex_list[i] = hex(int(bin_val, 2))

    # Truncate or extend the list to 16 elements
    hex_list = (hex_list[:16] if len(hex_list) > 16 else hex_list + ['0x0']*(16-len(hex_list)))

    return hex_list

def string_to_hex(input_string):
    hex_result = []
    for char in input_string:
        # Convert each character to its ASCII code (integer)
        char_code = ord(char)

        # Convert the ASCII code to hexadecimal and remove the '0x' prefix
        hex_char = hex(char_code)

        # Ensure each hexadecimal representation is 2 bits by adding leading zeros if needed
        hex_char = hex_char.zfill(2)
        hex_result.append(hex_char)
    return hex_result

def show_broken_ciphers():
    brokenCiphers = read_json("broken.json")["brokenCiphers"]
    if len(brokenCiphers) == 0:
        print("\nNo broken ciphers found")
        return
    else:
        print("\nFound", len(brokenCiphers), "broken ciphers:\n")
    for borkenCipher in brokenCiphers:
        print_short_line()
        print("Cipher:", borkenCipher["cipher"])
        print("Key in ASCII:", borkenCipher["key"])
        print("Deciphered text:", borkenCipher["plainText"])

def show_candidate_plain_texts():
    candidateCiphers = read_json("broken.json")["candidateCiphers"]
    if len(candidateCiphers) == 0:
        print("\nNo candidate plain texts found")
        return
    else:
        print("\nFound", len(candidateCiphers), "candidate plain texts:\n")
    for candidateCipher in candidateCiphers:
        print_short_line()
        print("Cipher:", candidateCipher["cipher"])
        print("Key in ASCII:", candidateCipher["key"])
        print("Deciphered text:", candidateCipher["plainText"])


def show_used_keys_history():
    ciphers = read_json("lastTriedBinary.json")["ciphers"]
    if len(ciphers) == 0:
        print("\nNo used keys history found")
        return
    else:
        print("\nFound", len(ciphers), "used keys history:\n")
    for cipher in ciphers:
        print_short_line()
        print("Cipher:", cipher["cipher"])
        print("Binary:", cipher["binary"])
        print_short_line()

def save_last_used_binary(cipher, binary):
    with open("lastTriedBinary.json", "r") as f:
        data = json.load(f)
        f.close()
    found = False
    for c in data["ciphers"]:
        if c["cipher"] == cipher:
            c["binary"] = binary
            found = True
            break
    if not found:
        data["ciphers"].append({"cipher": cipher, "binary": binary})

    with open("lastTriedBinary.json", "w") as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()
    
    print("Saved last used binary for cipher successfully")

def find_binary(cipher):
    with open("lastTriedBinary.json", "r") as f:
        data = json.load(f)
        f.close()
    for c in data["ciphers"]:
        if c["cipher"] == cipher:
            return c["binary"]
    return -1

def clear_broken_ciphers():
    with open("broken.json", "r") as f:
        data = json.load(f)
        f.close()
    count = len(data["brokenCiphers"])
    data["brokenCiphers"] = []

    with open("broken.json", "w") as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()
    
    print("\nCleared", count, "broken ciphers")

def clear_candidate_plain_texts():
    with open("broken.json", "r") as f:
        data = json.load(f)
        f.close()
    
    count = len(data["candidateCiphers"])
    data["candidateCiphers"] = []

    with open("broken.json", "w") as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()
    
    print("\nCleared", count, "candidate plain texts")

def clear_used_keys_history():
    with open("lastTriedBinary.json", "r") as f:
        data = json.load(f)
        f.close()
    
    count = len(data["ciphers"])
    data["ciphers"] = []

    with open("lastTriedBinary.json", "w") as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()
    
    print("\nCleared", count, "used keys history")

def clear_all_data():
    clear_broken_ciphers()
    clear_candidate_plain_texts()
    clear_used_keys_history()

def override_json(new_data, category, filename='broken.json'):
    with open(filename, 'r') as f:
        data = json.load(f)
        f.close()
    data[category] = new_data
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()

def write_json(new_data, category, filename='broken.json'):
    with open(filename,'r+') as file:
        file_data = json.load(file)
        file_data[category].append(new_data)
        file.seek(0)
        json.dump(file_data, file, indent = 4)
     
def read_json(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
        return data

def find_broken_cipher(cipher):
    brokenCiphers = read_json("broken.json")["brokenCiphers"]
    for brokenCipher in brokenCiphers:
        if brokenCipher["cipher"] == cipher:
            return brokenCipher
    return False

def get_matching_ciphers(cipher):
    candidateCiphers = read_json("broken.json")["candidateCiphers"]
    matching_ciphers = []
    for candidateCipher in candidateCiphers:
        if candidateCipher["cipher"] == cipher:
            matching_ciphers.append(candidateCipher)
    return matching_ciphers

def remove_candidate_ciphers(matchingCiphers):
    data = read_json("broken.json")
    candidateCiphers = data["candidateCiphers"]
    for matchingCipher in matchingCiphers:
        candidateCiphers.remove(matchingCipher)
    override_json(candidateCiphers, "candidateCiphers")

def remove_key_history(cipher):
    data = read_json("lastTriedBinary.json")
    ciphers = data["ciphers"]
    for c in ciphers:
        if c["cipher"] == cipher:
            ciphers.remove(c)
            break
    data["ciphers"] = ciphers
    with open("lastTriedBinary.json", "w") as f:
        json.dump(data, f, indent=4)
        f.seek(0)
        f.close()


def move_to_broken(cipher, binary, matchingCiphers):
    bad_input = True
    while bad_input:
        print("Leave it blank to exit")
        plainText = input("Enter the found plain text to move it to broken ciphers list: ")
        if plainText == "":
            print("\nExiting brute-force mode...")
            save_last_used_binary(cipher, binary)
            return False
    
        # Move the cipher from candidateCiphers to brokenCiphers
        for matchingCipher in matchingCiphers:
            if matchingCipher["plainText"] == plainText:
                write_json(matchingCipher, "brokenCiphers")
                bad_input = False
                print("Saved to broken ciphers list successfully!")
        if bad_input:
            print("Invalid plain text!")
    return True

def hexkey_to_binarykey(hexKey):
    return int("".join([bin(int(hexKey[i], 16))[2:].zfill(8) for i in range(len(hexKey)-1, -1, -1)]), 2)

def binarykey_to_hexkey(binary_key):
    binary_key = bin(binary_key)[2:].zfill(128)
    hexKey = [hex(int(binary_key[i-8:i], 2)) for i in range(129, 8, -8)]
    return hexKey

def get_last_candidate_key(matchingCiphers):
    hexKey = matchingCiphers[-1]["hexKey"]
    print("Last found candidate key:", hexKey)
    binary = hexkey_to_binarykey(hexKey)
    return binary

def get_all_candidate_ciphers():
    return read_json("broken.json")["candidateCiphers"]

def hexkey_to_char(hexKey):
    return "".join([chr(int(value, 16)) for value in hexKey]).replace("\u0000","")

def display_matrix(matrix, num_cols, col_title):
    all_matrix = []
    
    row_count = len(matrix[0])
    matrix_rows = []
    for i in range(row_count):
        matrix_rows.append([])

    count = math.ceil(len(matrix) / num_cols)

    while count > 0:
        # Convert columns to rows
        for col in range(num_cols if count > 1 else len(matrix)):
            for row in range(row_count):
                matrix_rows[row].append(matrix[col][row])
        
        all_matrix.append(matrix_rows)

        # Remove the first num_cols columns
        matrix = matrix[num_cols:]
        
        # reset matrix_rows
        matrix_rows = []
        for i in range(row_count):
            matrix_rows.append([])

        count -= 1

    count = 0
    for m in all_matrix:
        headers = []
        for i in range(len(m[0])):
            headers.append(col_title + str(count + i))
            
        count += len(m[0])
        
        print(tb.tabulate(m, headers=headers, tablefmt="fancy_grid"))


def generate_subkeys(KHexList):
    # put 44 empty lists inside subkeys44, each 4 lists is one subkey, each list is one column
    all_sub_keys_columns = [
        [KHexList[0], KHexList[1], KHexList[2], KHexList[3]],
        [KHexList[4], KHexList[5], KHexList[6], KHexList[7]],
        [KHexList[8], KHexList[9], KHexList[10], KHexList[11]],
        [KHexList[12], KHexList[13], KHexList[14], KHexList[15]],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
    ]

    print("\nS-Box to be used:")
    print(tb.tabulate(sbox_table, tablefmt="grid"))

    print("\nSubkeys 0-3:")
    display_matrix(all_sub_keys_columns[:4], 4, "col")
    # Subkeys generation #
    # The round_number is used to identify the round constant to use
    round_number = 1

    # Range is from 3 to 43, step is 4, because we already have the first 4 subkeys
    # In every loop, 4 subkeys are generated, so we need to loop 10 times to generate 40 subkeys
    print("\nGenerating remaining subkeys 4-43 in 10 rounds...\n")
    print("Each round consists of 4 steps:")
    print("1. Rotate column")
    print("2. Substitute values from S-Box")
    print("3. XOR with round constant to calculate g(col)")
    print("4. XOR with previous column to obtain next subkeys")

    for i in range(3, 43, 4):

        print_short_line()
        print("Round number: " + str(round_number) + "/10")

        # First select the column to rotate
        colToRotate = all_sub_keys_columns[i]
        print("\n1.")
        print("Column to rotate:", colToRotate, "at index", i)

        print("Rotating column...")

        # Then rotate it
        rotatedCol = colToRotate[1:] + colToRotate[:1]
        print("Rotated column:", rotatedCol)

        print("\n2.")
        print("Substituting values from S-Box...")

        # Then substitute new values according to the sbox
        substitutionCol = []
        for j in range(4):
            substitutionCol.append(hex(aes_sbox[int(rotatedCol[j], 16)]))
        print("Substituted column:", substitutionCol, "at index", i)

        print("\n3.")
        print(f"Calculating g(col{i})...")

        # Get the round constant
        rConCol = round_constants[round_number-1]
        print("Round constant:", rConCol)

        print(f"XORing substituted column with round constant to get g(col{i})...")

        # calculate g(col)
        gOfCol = []
        for j in range(4):
            gOfCol.append(hex(int(substitutionCol[j], 16) ^ rConCol[j]))
        print(f"g(col{i}):", gOfCol, "at index", i)

        print("\n4.")
        print(f"Generating subkeys {i+1}, {i+2}, {i+3}...")

        print(f"\nXORing g(col{i}) with col{i-3} to get subkey{i+1}...")

        # Get the 4 new subkeys
        nextCol = all_sub_keys_columns[i+1]
        for j in range(4):
            nextCol.append(hex(int(all_sub_keys_columns[i-3][j], 16) ^ int(gOfCol[j], 16)))
        print(f"Subkey{i+1}:", nextCol, "at index", i+1)

        for j in range(3):
            print(f"\nXORing subkey{i+j+1} with col{i-2+j} to get subkey{i+j+2}...")
            nextCol = all_sub_keys_columns[i+j+2]
            for k in range(4):
                nextCol.append(hex(int(all_sub_keys_columns[i-2+j][k], 16) ^ int(all_sub_keys_columns[i+j+1][k], 16)))
            print(f"Subkey{i+j+2}:", nextCol, "at index", i+j+2)

        new_subkeys = all_sub_keys_columns[i+1:i+5]
        print("\nSubkeys " + str(i+1) + "-" + str(i+4) + ":")
        display_matrix(new_subkeys, 4, "col")

        print("\nRound " + str(round_number) + " completed")

        round_number += 1
    
    print_long_line()
    print("Final Subkeys 0-43:")
    display_matrix(all_sub_keys_columns, 11, "col")
    return all_sub_keys_columns


def encrypt(plainText, key):
    ### Padding ###
    print_long_line()
    print("Starting encryption process...\n")
    print("Step 1: Padding")
    if check_to_pad(plainText):
        plainText = padding(plainText)
    else:
        print("No padding needed")

    print_long_line()
    # Convert plain text to hex
    print("Step 2: Convert plain text to hex")
    PTHexList = string_to_hex(plainText)
    print("Plain text in hex:", PTHexList)

    print_long_line()
    # If the key is not 128-bit, convert it to a 128-bit key
    print("Step 3: Convert key to a 128-bit key")
    KHexList = convert_to_128_bit(string_to_hex(key))
    print("Key in hex:", KHexList)

    ### CIPHERING ###
    # phase 1
    # Generate subkeys
    print_long_line()
    print("Step 4: Generate 44 subkeys")
    all_sub_keys_columns = generate_subkeys(KHexList)

    print_long_line()
    print("Step 5: Split plain text into 16-byte blocks")
    # Create message message_blocks
    message_blocks = []
    for i in range(0, len(PTHexList), 16):
        message_blocks.append(PTHexList[i:i+16])
    
    # Cipher blocks
    cipher_blocks = []

    for z, message_block in enumerate(message_blocks):
        msg_matrix = [
            [message_block[0], message_block[1], message_block[2], message_block[3]],
            [message_block[4], message_block[5], message_block[6], message_block[7]],
            [message_block[8], message_block[9], message_block[10], message_block[11]],
            [message_block[12], message_block[13], message_block[14], message_block[15]],
        ]

        print(f"\nMessage block {z}:", message_block)
        display_matrix(msg_matrix, 4, "col")

        state_array = [
            [],
            [],
            [],
            []
        ]

        # phase 2
        # Add round key step using subkeys 0-3
        print_long_line()
        print(f"Step 6: XORing subkeys 0-3 with message block {z} to obtain the state matrix")
        for i in range(4):
            for j in range(4):
                state_array[i].append(hex(int(msg_matrix[i][j], 16) ^ int(all_sub_keys_columns[i][j], 16)))
        display_matrix(state_array, 4, "col")

        print_long_line()
        print(f"Step 7: Starting the 10 rounds for message block {z}")
        print("\nEach round consists of 4 steps:")
        print("1. Substitution from S-Box")
        print("2. Rotate rows")
        print("3. Mix columns except round 10")
        print("4. Add round key")

        print_short_line()
        print("Standard matrix to be used:")
        print(tb.tabulate(standard_matrix, tablefmt="grid"))

        # The 10 rounds
        for round in range(1, 11):
            print_short_line()
            print(f"Round number: {round}/10")
            
            # Substitution from sbox
            print("\n1.")
            print("Substitution from S-Box into state matrix...")
            for i in range(4):
                for j in range(4):
                    state_array[i][j] = hex(aes_sbox[int(state_array[i][j], 16)])
            print("State matrix after substitution:")
            display_matrix(state_array, 4, "col")

            # change from columns to rows
            state_array_rows = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    state_array_rows[row].append(state_array[col][row])

            # rotate rows
            print("\n2.")
            print("Rotating rows...")
            for i in range(1, 4):
                state_array_rows[i] = state_array_rows[i][i:] + state_array_rows[i][:i]

            # change from rows to columns back again
            state_array = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    state_array[col].append(state_array_rows[row][col])
            print("State matrix after row rotation:")
            display_matrix(state_array, 4, "col")

            # mix columns step
            if round != 10:
                # Each list is a column
                arr = [
                    [],
                    [],
                    [],
                    []
                ]

                # Matrix multiplication in GF(2^8)
                print("\n3.")
                print("Mixing columns...")
                print("Multiplying state matrix with standard matrix...")
                for i in range(4):
                    for j in range(4):
                        part1 = gf_2_8_product(int(standard_matrix[j][0], 16), int(state_array[i][0], 16))
                        part2 = gf_2_8_product(int(standard_matrix[j][1], 16), int(state_array[i][1], 16))
                        part3 = gf_2_8_product(int(standard_matrix[j][2], 16), int(state_array[i][2], 16))
                        part4 = gf_2_8_product(int(standard_matrix[j][3], 16), int(state_array[i][3], 16))
                        r = part1 ^ part2 ^ part3 ^ part4
                        arr[i].append(hex(r))

                state_array = arr
                print("State matrix after mixing columns:")
                display_matrix(state_array, 4, "col")

            # Add round key step using the next 4 subkeys
            print("\n4.")
            print("Adding round key...")
            print(f"XORing state matrix with subkeys {round*4} to {round*4+3}...")
            for i in range(4):
                for j in range(4):
                    sub_key_index = (round)*4 + j
                    state_array[i][j] = hex(int(state_array[i][j], 16) ^ int(all_sub_keys_columns[sub_key_index][j], 16))
            print("State matrix after adding round key:")
            display_matrix(state_array, 4, "col")

            print("\nRound", round, "completed")
            print("Obtained cipher block:")
            display_matrix(state_array, 4, "col")

        cipher_blocks.append(state_array)

    print_long_line()
    print("Cipher blocks:")
    cipher = ""
    for cipher_block in cipher_blocks:
        display_matrix(cipher_block, 4, "col")
        for i in range(4):
            for j in range(4):
                cipher += cipher_block[i][j][2:].zfill(2)
    
    clipboard.copy(cipher)
    print_long_line()
    print("Ciphered text (Copied to clipboard):", cipher)
    print_long_line()

    return cipher


def decrypt(cipher, key):
    ### DECIPHERING ###
    # Do the reverse of the ciphering process
    print_long_line()
    print("Starting decryption process...\n")
    print("Step 1: Generate 44 subkeys")
    if type(key) == str:
        all_sub_keys_columns = generate_subkeys(convert_to_128_bit(string_to_hex(key)))
    elif type(key) == list:
        # If brute-force is used, the key is already a list of hexs
        all_sub_keys_columns = generate_subkeys(key)
    
    # Retain the cipher blocks
    print_long_line()
    print("Step 2: Split cipher into 16-byte blocks:")
    cipher_blocks = []
    for i in range(0, len(cipher), 2):
        cipher_blocks.append(hex(int(cipher[i:i+2], 16)))
    cipher_blocks = [cipher_blocks[i:i+4] for i in range(0, len(cipher_blocks), 4)]
    cipher_blocks = [cipher_blocks[i:i+4] for i in range(0, len(cipher_blocks), 4)]

    for cipher_block in cipher_blocks:
        display_matrix(cipher_block, 4, "col")
    
    deciphered_blocks = []

    print_long_line()
    print("Step 3: Starting the 10 rounds for each cipher block")
    print("\nEach round consists of 4 steps:")
    print("1. Add round key")
    print("2. Mix columns except round 1")
    print("3. Rotate rows")
    print("4. Substitution from inverse S-Box")

    print_short_line()
    print("Inverse S-Box to be used:")
    print(tb.tabulate(inverse_aes_sbox_table, tablefmt="grid"))
    print_short_line()
    print("Inverse standard matrix to be used:")
    print(tb.tabulate(inverse_standard_matrix, tablefmt="grid"))

    for cipher_block in cipher_blocks:
        # 10 rounds
        for round in range(1, 11):
            print_short_line()
            print(f"Round number: {round}/10")

            # Add round key step starting from the last 4 subkeys 40-43
            print("\n1.")
            print(f"Adding round key {4*(11-round)} to {4*(11-round)+3}...")
            print(f"XORing cipher block with subkeys {4*(11-round)} to {4*(11-round)+3}...")
            for i in range(4):
                for j in range(4):
                    sub_key_index = (11-round)*4 + j
                    cipher_block[i][j] = hex(int(cipher_block[i][j], 16) ^ int(all_sub_keys_columns[sub_key_index][j], 16))

            print("Cipher block after adding round key:")
            display_matrix(cipher_block, 4, "col")

            # mix columns step
            if round != 1:
                # Each list is a column
                arr = [
                    [],
                    [],
                    [],
                    []
                ]

                # Matrix multiplication in GF(2^8) with inverse standard matrix
                print("\n2.")
                print("Mixing columns...")
                print("Multiplying cipher block with inverse standard matrix...")
                for i in range(4):
                    for j in range(4):
                        part1 = gf_2_8_product(int(inverse_standard_matrix[j][0], 16), int(cipher_block[i][0], 16))
                        part2 = gf_2_8_product(int(inverse_standard_matrix[j][1], 16), int(cipher_block[i][1], 16))
                        part3 = gf_2_8_product(int(inverse_standard_matrix[j][2], 16), int(cipher_block[i][2], 16))
                        part4 = gf_2_8_product(int(inverse_standard_matrix[j][3], 16), int(cipher_block[i][3], 16))
                        r = part1 ^ part2 ^ part3 ^ part4
                        arr[i].append(hex(r))

                cipher_block = arr
                print("Cipher block after mixing columns:")
                display_matrix(cipher_block, 4, "col")

            # change from columns to rows
            cipher_block_rows = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    cipher_block_rows[row].append(cipher_block[col][row])
            
            # rotate rows to the right instead of left
            print("\n3.")
            print("Rotating rows...")
            for i in range(1, 4):
                cipher_block_rows[i] = cipher_block_rows[i][4-i:] + cipher_block_rows[i][:4-i]
            
            # change from rows to columns back again
            cipher_block = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    cipher_block[col].append(cipher_block_rows[row][col])

            print("Cipher block after row rotation:")
            display_matrix(cipher_block, 4, "col")

            # Substitution from inverse sbox
            print("\n4.")
            print("Substitution from inverse S-Box into cipher block...")
            for i in range(4):
                for j in range(4):
                    cipher_block[i][j] = hex(inverse_aes_sbox[int(cipher_block[i][j], 16)])
            print("Cipher block after substitution:")
            display_matrix(cipher_block, 4, "col")


        # ADD round key step using subkeys 0-3
        print_long_line()
        print("Step 4: XORing subkeys 0-3 with cipher block to obtain the deciphered block")
        for i in range(4):
            for j in range(4):
                cipher_block[i][j] = hex(int(cipher_block[i][j], 16) ^ int(all_sub_keys_columns[i][j], 16))
        print("Deciphered block:")
        display_matrix(cipher_block, 4, "col")
        deciphered_blocks.append(cipher_block)

    print_long_line()
    print("Deciphered blocks:")
    # Plain text back again
    deciphered_text = ""
    for deciphered_block in deciphered_blocks:
        display_matrix(deciphered_block, 4, "col")
        for i in range(4):
            for j in range(4):
                deciphered_text += chr(int(deciphered_block[i][j], 16))

    print("\nDeciphered text with padding:", repr(deciphered_text))
    print("Removing padding...")
    deciphered_text = removePadding(deciphered_text)
    print_long_line()
    print("Deciphered text:", repr(deciphered_text))
    print_long_line()
    return deciphered_text


def removePadding_noprint(msg):
    # Need to check if padding has been done
    try:
        padding_length = int(msg[-1], 16) + 1
    except ValueError:
        return msg

    # Count the number of padding characters
    count = 0
    for char in range(padding_length - 1):
        if msg[-(char+2)] == "0":
            count += 1
        else:
            break
    if count == (padding_length - 1):
        while padding_length > 0:
            msg = msg[:-1]
            padding_length -= 1
    return msg


def generate_subkeys_noprint(KHexList):
    # put 44 empty lists inside subkeys44, each 4 lists is one subkey, each list is one column
    all_sub_keys_columns = [
        [KHexList[0], KHexList[1], KHexList[2], KHexList[3]],
        [KHexList[4], KHexList[5], KHexList[6], KHexList[7]],
        [KHexList[8], KHexList[9], KHexList[10], KHexList[11]],
        [KHexList[12], KHexList[13], KHexList[14], KHexList[15]],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
        [],[],[],[],
    ]

    # Subkeys generation #
    # The round_number is used to identify the round constant to use
    round_number = 1

    # Range is from 3 to 43, step is 4, because we already have the first 4 subkeys
    # In every loop, 4 subkeys are generated, so we need to loop 10 times to generate 40 subkeys
    for i in range(3, 43, 4):
        # First select the column to rotate
        colToRotate = all_sub_keys_columns[i]

        # Then rotate it
        rotatedCol = colToRotate[1:] + colToRotate[:1]

        # Then substitute new values according to the sbox
        substitutionCol = []
        for j in range(4):
            substitutionCol.append(hex(aes_sbox[int(rotatedCol[j], 16)]))

        # Get the round constant
        rConCol = round_constants[round_number-1]

        # calculate g(col)
        gOfCol = []
        for j in range(4):
            gOfCol.append(hex(int(substitutionCol[j], 16) ^ rConCol[j]))

        # Get the 4 new subkeys
        nextCol = all_sub_keys_columns[i+1]
        for j in range(4):
            nextCol.append(hex(int(all_sub_keys_columns[i-3][j], 16) ^ int(gOfCol[j], 16)))

        for j in range(3):
            nextCol = all_sub_keys_columns[i+j+2]
            for k in range(4):
                nextCol.append(hex(int(all_sub_keys_columns[i-2+j][k], 16) ^ int(all_sub_keys_columns[i+j+1][k], 16)))

        round_number += 1

    return all_sub_keys_columns


def decrypt_noprint(cipher, key):
    ### DECIPHERING ###
    # Do the reverse of the ciphering process
    if type(key) == str:
        all_sub_keys_columns = generate_subkeys_noprint(convert_to_128_bit(string_to_hex(key)))
    elif type(key) == list:
        # If brute-force is used, the key is already a list of hexs
        all_sub_keys_columns = generate_subkeys_noprint(key)
    
    # Retain the cipher blocks
    cipher_blocks = []
    for i in range(0, len(cipher), 2):
        cipher_blocks.append(hex(int(cipher[i:i+2], 16)))
    cipher_blocks = [cipher_blocks[i:i+4] for i in range(0, len(cipher_blocks), 4)]
    cipher_blocks = [cipher_blocks[i:i+4] for i in range(0, len(cipher_blocks), 4)]

    deciphered_blocks = []

    for cipher_block in cipher_blocks:
        # 10 rounds
        for round in range(1, 11):
            # Add round key step starting from the last 4 subkeys 40-43
            for i in range(4):
                for j in range(4):
                    sub_key_index = (11-round)*4 + j
                    cipher_block[i][j] = hex(int(cipher_block[i][j], 16) ^ int(all_sub_keys_columns[sub_key_index][j], 16))

            # mix columns step
            if round != 1:
                # Each list is a column
                arr = [
                    [],
                    [],
                    [],
                    []
                ]

                # Matrix multiplication in GF(2^8) with inverse standard matrix
                for i in range(4):
                    for j in range(4):
                        part1 = gf_2_8_product(int(inverse_standard_matrix[j][0], 16), int(cipher_block[i][0], 16))
                        part2 = gf_2_8_product(int(inverse_standard_matrix[j][1], 16), int(cipher_block[i][1], 16))
                        part3 = gf_2_8_product(int(inverse_standard_matrix[j][2], 16), int(cipher_block[i][2], 16))
                        part4 = gf_2_8_product(int(inverse_standard_matrix[j][3], 16), int(cipher_block[i][3], 16))
                        r = part1 ^ part2 ^ part3 ^ part4
                        arr[i].append(hex(r))

                cipher_block = arr

            # change from columns to rows
            cipher_block_rows = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    cipher_block_rows[row].append(cipher_block[col][row])
            
            # rotate rows to the right instead of left
            for i in range(1, 4):
                cipher_block_rows[i] = cipher_block_rows[i][4-i:] + cipher_block_rows[i][:4-i]
            
            # change from rows to columns back again
            cipher_block = [
                [],
                [],
                [],
                []
            ]

            for col in range(4):
                for row in range(4):
                    cipher_block[col].append(cipher_block_rows[row][col])

            # Substitution from inverse sbox
            for i in range(4):
                for j in range(4):
                    cipher_block[i][j] = hex(inverse_aes_sbox[int(cipher_block[i][j], 16)])


        # ADD round key step using subkeys 0-3
        for i in range(4):
            for j in range(4):
                cipher_block[i][j] = hex(int(cipher_block[i][j], 16) ^ int(all_sub_keys_columns[i][j], 16))
        deciphered_blocks.append(cipher_block)

    # Plain text back again
    deciphered_text = ""
    for deciphered_block in deciphered_blocks:
        for i in range(4):
            for j in range(4):
                deciphered_text += chr(int(deciphered_block[i][j], 16))

    deciphered_text = removePadding_noprint(deciphered_text)
    return deciphered_text

def brute_force(cipher, plain_text="", ignoreJSON=False, b=0):
    # Check if the cipher has been brute-forced before and get the last key used
    binary = find_binary(cipher)
    if binary == -1:
        # If the cipher has not been brute-forced before, start from the beginning or from the last key stopped at
        binary = b

    # Check if the cipher has already been broken
    brokenCipher = find_broken_cipher(cipher)
    if brokenCipher:
        print()
        print_long_line()
        print("Cipher already broken")
        print("Key in hex:", brokenCipher["hexKey"])
        print("Key in ASCII:", brokenCipher["key"])
        print("Deciphered text:", brokenCipher["plainText"])
        print_long_line()
        return
    
    # Check if the cipher has already been tried before and has candidate plain texts
    if not ignoreJSON:
        matchingCiphers = get_matching_ciphers(cipher)
    
        if len(matchingCiphers) > 0:
            # Display the candidate plain texts
            print("\nFound", len(matchingCiphers), "candidate deciphered texts:\m")
            for matchingCipher in matchingCiphers:
                print_short_line()
                print("Key in hex:", matchingCipher["hexKey"])
                print("Key in ASCII:", matchingCipher["key"])
                print("Deciphered text:", matchingCipher["plainText"])
                print_short_line()

            found = input("Is the plain text you are looking for in the above list? (y/n): ")
            if found.strip().lower() == "y":
                # Try to move the cipher from candidate to broken
                if move_to_broken(cipher, binary, matchingCiphers):
                    # Remove the ciphers from candidateCiphers
                    remove_candidate_ciphers(matchingCiphers)
                    # Remove the cipher from lastTriedBinary
                    remove_key_history(cipher)
                return
            elif found == "n":
                print("Continuing the brute-force after last tried key for this cipher...")
                binary = find_binary(cipher)
                if binary == -1:
                    print("No last tried key found for this cipher")
                    print("Continuing the brute-force after last tried candidate plain text key ...")
                    binary = get_last_candidate_key(matchingCiphers)
            else:
                print("Invalid choice!")
                save_last_used_binary(cipher, binary)
                return
        
    time.sleep(3)

    matchingCiphers = []

    for i in range(binary, 2**128):
        try:
            hexKey = binarykey_to_hexkey(binary)
            print_long_line()
            print("Iteration:", binary)
            print("Trying hex key:", hexKey)
            deciphered_text = decrypt_noprint(cipher, hexKey)

            if plain_text != "":
                if deciphered_text == plain_text:

                    # Convert the key to ASCII
                    key = hexkey_to_char(hexKey)

                    # Save to broken ciphers
                    write_json({"cipher": cipher, "key": key, "hexKey": hexKey, "plainText": deciphered_text}, "brokenCiphers")

                    # Remove the ciphers from candidateCiphers
                    matchingCiphers = get_matching_ciphers(cipher)
                    remove_candidate_ciphers(matchingCiphers)

                    # Remove the cipher from lastTriedBinary
                    remove_key_history(cipher)

                    
                    print("\n****************************************Cipher broken successfully!****************************************")
                    print("Key found:", hexKey)
                    print("Key in ASCII:", key)
                    print("Iterations:", binary)
                    print("Deciphered text:", deciphered_text)
                    print("Plain text:", plain_text)
                    print("*************************************************************************************************************")
                    print("\nCipher saved to broken ciphers list successfully")

                    return
                    
            elif bytes(deciphered_text, "utf-8").isascii():
                key = hexkey_to_char(hexKey)

                # Save to candidate ciphers
                write_json({"cipher": cipher, "key": key, "hexKey": hexKey, "plainText": deciphered_text}, "candidateCiphers")

                print("\n****************************************Cipher broken successfully!****************************************")
                print("Key found:", hexKey)
                print("Key in ASCII:", key)
                print("Iterations:", binary)
                print("Deciphered text:", deciphered_text)
                print("Plain text:", plain_text)
                print("*************************************************************************************************************")    

                print("\nPlain text saved to candidate plain texts list successfully")

                time.sleep(5)   

            binary += 1

        except KeyboardInterrupt:
            print("\nStopping the brute-force...\n")

            # Show candidate ciphers
            print("Showing candidate ciphers:")
            matchingCiphers = get_matching_ciphers(cipher)
            print("\nFound", len(matchingCiphers), "candidate deciphered texts")

            if len(matchingCiphers) > 0:
                for matchingCipher in matchingCiphers:
                    print_short_line()
                    print("Key in hex:", matchingCipher["hexKey"])
                    print("Key in ASCII:", matchingCipher["key"])
                    print("Deciphered text:", matchingCipher["plainText"])
                    print_short_line()
                
                found = input("\nIs the plain text you are looking for in the above list? (y/n): ")
                if found.strip().lower() == "y":
                    # Try to move the cipher from candidate to broken
                    if move_to_broken(cipher, binary, matchingCiphers):
                        # Remove the ciphers from candidateCiphers
                        remove_candidate_ciphers(matchingCiphers)
                        # Remove the cipher from lastTriedBinary
                        remove_key_history(cipher)
                    return
                elif found == "n":
                    cont = input("Do you wish to continue the brute-force? (y/n): ")
                    if cont.strip().lower() == "y":
                        print("Continuing the brute-force after last used key ...")
                    else:
                        save_last_used_binary(cipher, binary)
                        return
                else:
                    print("Invalid choice!")
                    save_last_used_binary(cipher, binary)
                    return
            
            elif len(matchingCiphers) == 0:
                cont = input("Do you wish to continue the brute-force? (y/n): ")
                if cont.strip().lower() == "y":
                    print("Continuing the brute-force after last used key ...")
                else:
                    save_last_used_binary(cipher, binary)
                    return
                


