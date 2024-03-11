# timecapsule
Send secrets into the future

**not ready yet**

## About
TimeCapsule is a cryptographic tool that allows you to encrypt messages that can only be decrypted after a certain time. This allows you to send messages to the future, and guarantee that they will not be read until a specific date.

Let's go over the details of how this works.

TimeCapsule depends on a central server that generates hashes based on the current time in unix timestamp. So, every second, a new cryptographic hash will be generated. This hash will come handy later.

When you want to encrypt a message, you also need to specify a duration, in seconds, for how long you want the message to be locked. Once you have your message and the duration pair, the server calculates the future hash using the duration. Then, it generates a key by creating random bytes and xor-ing them with the hash. With this key, we encrypt the message by xor-ing it with the key. After that, the recipient receives the encrypted message, the key and the future timestamp.

To decrypt the message, we need two things. The hash and the key. We have the key already, what we need is the hash.

The hash is generated by the server based on a couple things. It all starts with a secret that only the server knows, and a sequence of bits with length 1009152000. For each hashing operation we use the previous hash, a timestamp, and a bit from the sequence with a specific index.

Also, the server knows its own epoch, which is just a timestamp of when the program started. To generate the hash for a future timestamp, we find out the seconds that will pass from the server's epoch to the future timestamp. Then, starting with the secret, for each timestamp from the epoch to the future timestamp, we hash the combination of secret, timestamp and the bit that corresponds to the number of seconds that will pass from the sequence. Because of this, only the server can generate the hash for a specific future timestamp.

So, when the future timestamp arrives, the recipient can ask the server for the hash, and then decrypt the message using the key and the hash. This way, the message is guaranteed to be locked until the specified time.

## Usage
TimeCapsule has a simple command line interface. You can use it to encrypt and decrypt messages.

To encrypt a message, you need to specify the message and the duration in seconds. Here's an example:

```
$ timecapsule encrypt "Hello, future!" 3600
```

This will output a JSON object with the encrypted message, the key and the future timestamp.

To decrypt a message, you need the key and the future timestamp. Here's an example:

```
$ timecapsule decrypt message.json
```

Where `message.json` is a file containing the encrypted message, the key and the future timestamp.