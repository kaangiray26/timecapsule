#!env/bin/python
# -*- coding: utf-8 -*-

import os
import json
import hashlib
import secrets
import time
import base64
from datetime import datetime
import argparse

class TimeCapsule:
    def __init__(self):
        # Config
        self.epoch = None
        self.secret = None
        self.last_timestamp = None
        self.last_timedhash = None
        
        # Random bit sequence
        self.bit_sequence = None
        
        # Read config on init
        self.read_config()

    def read_config(self):
        if "config.json" not in os.listdir("."):
            # Create config file if not exists
            print("Creating config file...")
            with open("config.json", "w") as f:
                config = {
                    "secret": secrets.token_hex(32),
                    "epoch": int(time.time()),
                    "last_timestamp": None,
                    "last_timedhash": None,
                }
                json.dump(config, f, indent=4)
            print("Please run the program again.")
            exit(0)

        if "bit_sequence" not in os.listdir("."):
            # Also create a bit sequence of length 1009152000,
            # which is the number of seconds in 32 years.
            # Therefore, we have 126144000 bytes of random data.
            print("Creating bit sequence...")
            with open("bit_sequence", "wb") as f:
                bit_sequence = secrets.token_bytes(126144000)
                f.write(bit_sequence)

        # Read config file
        with open("config.json") as f:
            config = json.load(f)
            self.secret = config["secret"]
            self.epoch = config["epoch"]
            self.last_timestamp = config["last_timestamp"]
            self.last_timedhash = config["last_timedhash"]

        # Read bit sequence
        with open("bit_sequence", "rb") as f:
            self.bit_sequence = f.read()

    def save_config(self):
        print("Saving config...")
        with open("config.json", "w") as f:
            config = {
                "secret": self.secret,
                "epoch": self.epoch,
                "last_timestamp": self.last_timestamp,
                "last_timedhash": self.last_timedhash,
            }
            json.dump(config, f, indent=4)

    def get_bit(self, index):
        byte_index = index // 8
        bit_index = index % 8
        byte = self.bit_sequence[byte_index]
        return (byte >> bit_index) & 1

    def hash(self, last_timedhash, timestamp):
        bit = self.get_bit(timestamp-self.epoch)
        body = f"{last_timedhash}{self.secret}{timestamp+1}{bit}"
        return hashlib.sha256(body.encode()).hexdigest()

    def xor(self, a, b):
        return "".join([chr(ord(a[i]) ^ ord(b[i])) for i in range(len(a))])

    def calculate_timedhash(self, timestamp):
        # Calculate timedhash from the epoch
        if self.last_timedhash is None:
            self.last_timedhash = self.secret
            for i in range(timestamp - self.epoch):
                self.last_timedhash = self.hash(self.last_timedhash, self.epoch+i)
            self.last_timestamp = timestamp
            return f"{timestamp} :: {self.last_timedhash}"

        # Calculate timedhash from the last timedhash
        for i in range(timestamp - self.last_timestamp):
            self.last_timedhash = self.hash(self.last_timedhash, self.last_timestamp+i)
        self.last_timestamp = timestamp
        return f"{timestamp} :: {self.last_timedhash}"
    
    def encrypt(self, message, duration):
        # Calculate timestamp
        timestamp = int(time.time()) + duration
        self.calculate_timedhash(timestamp)

        # Create key for encryption
        key = secrets.token_hex(32)
        encryption_key = self.xor(self.last_timedhash, key)

        # Encrypt message
        encrypted_message = self.xor(message, encryption_key)
        b64_message = base64.b64encode(encrypted_message.encode()).decode()

        with open("message.json", "w") as f:
            data = {
                "key": key,
                "message": b64_message,
                "timestamp": timestamp,
            }
            json.dump(data, f, indent=4)
        
        print("Message saved to message.json")
        return
    
    def decrypt(self, file):
        data = {}
        with open(file) as f:
            data = json.load(f)
        
        # Ask for hash
        hash = input("Enter the hash: ")

        # Decrypt message
        decryption_key = self.xor(hash, data['key'])
        decoded_b64_message = base64.b64decode(data['message']).decode()
        decrypted_message = self.xor(decoded_b64_message, decryption_key)
        print("Decrypted message:", decrypted_message)
        
    def handle_args(self, args):
        if args.run:
            self.run()
            return

        if args.encrypt:
            print("Encrypting message...")
            self.encrypt(args.encrypt[0], int(args.encrypt[1]))
            return
        
        if args.decrypt:
            self.decrypt(args.decrypt[0])
            return

    def run(self):
        now = int(time.time())
        future = now + 1009152000
        print("Encryption until:", datetime.fromtimestamp(future))
        print("")
        print("Time capsule Running...")
        print("Now:", now)
        
        while True:
            print(self.calculate_timedhash(now))
            now += 1
            time.sleep(1)

if __name__ == "__main__":
    capsule = TimeCapsule()
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", help="Run the time capsule", action="store_true")
    parser.add_argument("--encrypt", help="Encrypt a message", nargs=2, metavar=("message", "duration"))
    parser.add_argument("--decrypt", help="Decrypt a message", nargs=1, metavar=("file"))

    args = parser.parse_args()

    try:
        # capsule.run()
        # capsule.run_test()
        capsule.handle_args(args)
    except KeyboardInterrupt:
        capsule.save_config()