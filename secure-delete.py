import os
import argparse
import secrets
import time
import string
import gc
import ctypes
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from TwoFish import TwoFish_encrypt, text_To_Hex, hex_To_Text

def clear_memory_random_ctypes(data):
    if not isinstance(data, (bytearray, memoryview)):
        raise TypeError("Data must be a writable buffer, such as bytearray or memoryview.")
    
    data_len = len(data)
    ptr = (ctypes.c_char * data_len).from_buffer(data)
    for _ in range(5):
        random_data = secrets.token_bytes(data_len)
        ctypes.memmove(ptr, random_data, data_len)  # メモリの内容をランダムデータで上書き
        del random_data  # ランダムデータを削除
        
    for _ in range(2):
        ctypes.memset(ptr, 0, data_len)
        
    del ptr
    gc.collect()  # ガベージコレクションを試みる
#    gc.garbage

def double_encrypt_with_aes_twofish(filename, no_debug):
    """指定されたファイルをAESとTwofishで暗号化し、メモリの安全を確保"""
    # ファイルを読み込み
    with open(filename, 'rb') as f:
        if not no_debug:
            print(f"{filename} is now reading for encryption")
        data = bytearray(f.read())  # バイト配列として読み込み、書き換え可能にする
        if not no_debug:
            print(f"{filename} is Readed")

    # AESの設定
    aes_key = bytearray(secrets.token_bytes(32))
    aes_iv = bytearray(secrets.token_bytes(16))
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    clear_memory_random_ctypes(aes_key)
    clear_memory_random_ctypes(aes_iv)
    del aes_key, aes_iv
    if not no_debug:
        print(f"Now created AES-256bit config and 7 trying(5random & 2try 0 padding and delete variable+collect Garbage) overwrite key and iv on ram")

    # データをAESで暗号化
    padded_data = pad(data, AES.block_size)  # パディングされたデータ
    clear_memory_random_ctypes(data)
    del data
    encrypted_data = bytearray(aes_cipher.encrypt(padded_data))
    del aes_cipher
    clear_memory_random_ctypes(padded_data)
    del padded_data
    if not no_debug:
        print(f"{filename} Encrypted data is saved on ram")

    # AES暗号化結果を16進文字列に変換
    encrypted_data_hex = encrypted_data.hex()

    # メモリクリア
    clear_memory_random_ctypes(encrypted_data)
    del encrypted_data

    # Twofishの設定
    twofish_key = bytearray(secrets.token_bytes(16))
    twofish_encrypted_data_hex = TwoFish_encrypt(encrypted_data_hex, twofish_key.hex(), "ECB")
    
    # Twofishキーのクリア
    clear_memory_random_ctypes(twofish_key)
    del twofish_key
    # AES暗号化結果（16進文字列）のメモリクリア
    clear_memory_random_ctypes(bytearray(encrypted_data_hex, 'utf-8'))
    del encrypted_data_hex
    if not no_debug:
        print(f"{filename} is now twofish-256bit encrypt is saved on ram and delete old encryption and encryption key")

    # Twofish暗号化結果をバイナリ形式に変換
    doubly_encrypted_data = bytes.fromhex(twofish_encrypted_data_hex)

    # Twofish暗号化結果（16進文字列）のメモリクリア
    clear_memory_random_ctypes(bytearray(twofish_encrypted_data_hex, 'utf-8'))
    del twofish_encrypted_data_hex

    # ファイルに書き込み
    with open(filename, 'wb') as f:
        f.truncate(0)
        f.write(doubly_encrypted_data)

    # Twofish暗号化結果のクリア
    clear_memory_random_ctypes(bytearray(doubly_encrypted_data))
    del doubly_encrypted_data

    gc.collect()  # 最後にガベージコレクションを呼び出し

    if not no_debug:
        print(f"{filename} is Encrypted by AES+Twofish")

def corrupt_step(filename, filesize, pattern):
    if len(pattern) == 0:
        return

    with open(filename, 'wb') as fp:
        for _ in range(filesize // len(pattern) + 1):
            fp.write(pattern)

def secure_erase(filename, filesize, no_debug):
    def write_random_bytes(fp, size):
        # Securely write random bytes to the file
        for _ in range(size):
            fp.write(secrets.token_bytes(filesize))
    
    with open(filename, 'r+b') as fp:
        if not no_debug:
            print(f"Rewriting with NSA method {filename}... (1/3)")
        write_random_bytes(fp, filesize)
        fp.seek(0)
        if not no_debug:
            print(f"Rewriting with NSA method {filename}... (2/3)")
        write_random_bytes(fp, filesize)
        fp.seek(0)
        if not no_debug:
            print(f"Rewriting with NSA method {filename}... (3/3)")
        fp.write(b"\x00" * filesize)

def random_string(length):
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

def corrupt_directory(directory, no_debug):
    # ディレクトリ内のファイルを再帰的に削除
    for root, dirs, files in os.walk(directory, topdown=False):
        for file in files:
            file_path = os.path.join(root, file)
            corrupt_file(file_path, no_debug)  # ファイルをグートマン方式で削除
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            corrupt_directory(dir_path, no_debug)  # ディレクトリを再帰的に削除

    # ディレクトリ名をランダムな文字列で書き換え（35回）
    for i in range(35):
        new_dir_name = random_string(10)
        if not no_debug:
            print(f"Randomly renaming {directory} to {new_dir_name}... ({i+1}/35)")
        os.rename(directory, os.path.join(os.path.dirname(directory), new_dir_name))
        directory = os.path.join(os.path.dirname(directory), new_dir_name)

    # ディレクトリを削除
    try:
        os.rmdir(directory)
        if not no_debug:
            print(f"{directory} is deleted!")

    except FileNotFoundError:
        if not no_debug:
            print(f"corrupt: '{directory}' not found")
    except Exception as e:
        if not no_debug:
            print(f"corrupt: error occurred while shredding '{directory}': {e}")

def corrupt_file(filename, no_debug):
    try:
        filesize = os.path.getsize(filename)
        steps = [b"\x00", b"\x00", b"\x00", b"\x00", b"\x55", b"\xAA",
                 b"\x92\x49\x24", b"\x49\x24\x92",
                 b"\x24\x92\x49", b"\x00", b"\x11",
                 b"\x22", b"\x33", b"\x44", b"\x55",
                 b"\x66", b"\x77", b"\x88", b"\x99",
                 b"\xAA", b"\xBB", b"\xCC", b"\xDD",
                 b"\xEE", b"\xFF", b"\x92\x49\x24",
                 b"\x49\x24\x92", b"\x24\x92\x49",
                 b"\x6D\xB6\xDB", b"\xB6\xDB\x6D",
                 b"\xDB\x6D\xB6", b"\x00", b"\x00", b"\x00", b"\x00"]

        double_encrypt_with_aes_twofish(filename, no_debug)
        for i, step in enumerate(steps):
            corrupt_step(filename, filesize, step)
            if not no_debug:
                print(f"Rewriting with Gutmann method {filename}... ({i+1}/{len(steps)})")

        secure_erase(filename, filesize, no_debug)

        # ファイル名をランダムな文字列で書き換え（35回）
        for i in range(35):
            new_file_name = random_string(10)
            if not no_debug:
                print(f"Randomly renaming {filename} to {new_file_name}... ({i+1}/35)")
            os.rename(filename, os.path.join(os.path.dirname(filename), new_file_name))
            filename = os.path.join(os.path.dirname(filename), new_file_name)

        # ファイルを削除
        os.remove(filename)
        if not no_debug:
            print(f"{filename} is deleted!")

    except FileNotFoundError:
        if not no_debug:
            print(f"corrupt: '{filename}' not found")
    except Exception as e:
        if not no_debug:
            print(f"corrupt: error occurred while shredding '{filename}': {e}")

def corrupt_file_or_directory(path, no_debug):
    if os.path.isfile(path):
        # ファイルが存在する場合、ファイルをグートマン方式で削除
        corrupt_file(path, no_debug)

    elif os.path.isdir(path):
        # ディレクトリが存在する場合、ディレクトリ内のファイルを削除してからディレクトリを削除
        corrupt_directory(path, no_debug)

def main():
    parser = argparse.ArgumentParser(description=(        "Shreds files and directories using the Gutmann method (HDD recommend), "
        "and NSA method (random random zero / SSD recommend), "
        "and AES-256bit (random iv+key) + Twofish-256bit (random key) encryption, "
        "and renames with random values.\n"
        "This is a military-grade method for handling confidential information, "
        "and is generally used in scenarios such as deleting personal information "
        "or in situations where there is a risk of swatting. Use with caution.\n"
        "Created by milkey_saurus\n"
        "Version: 1.0.1"
    ), formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("path", nargs="+", help="Files or directories to shred")
    parser.add_argument("-nd", "--NoDebug", action="store_true", help="Suppress debug output")
    parser.add_argument("-bm", "--benchmark", action="store_true", help="Measure and display the time taken for processing")
    args = parser.parse_args()

    # ベンチマークモードの場合、開始時間を記録
    if args.benchmark:
        start_time = time.monotonic()

    for path in args.path:
        corrupt_file_or_directory(path, args.NoDebug)

    # ベンチマークモードの場合、終了時間を記録し、経過時間を計算・表示
    if args.benchmark:
        end_time = time.monotonic()
        elapsed_time = end_time - start_time
        
        # 経過時間をHour:min:second.millisecondsで表示
        hours, remainder = divmod(elapsed_time, 3600)
        minutes, seconds = divmod(remainder, 60)
        milliseconds = (seconds % 1) * 1000
        print("Time: {:0>2}:{:0>2}:{:05.2f}".format(int(hours), int(minutes), int(seconds)+(milliseconds / 1000)))

if __name__ == "__main__":
    main()
