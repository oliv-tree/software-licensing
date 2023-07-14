import uuid
import os
import getpass
import hashlib
import hmac
import random

# notes
# account instead of license key? that way they can login to reset device


def get_fingerprint():
	mac = hex(uuid.getnode())
	name = os.environ["COMPUTERNAME"]
	username = getpass.getuser()
	serial = os.popen("wmic csproduct get uuid").read().replace("\n","").replace(" ","")  # note: only works for windows
	fingerprint = hashlib.sha3_256((mac + name + username + serial).encode("utf-8")).hexdigest()
	return fingerprint


def generate_hmac():
	key = b''  # TODO: get from credentials.json
	# key = bytes(hex(random.getrandbits(128)).encode("utf-8"))
	h = hmac.new(key, "true".encode("utf-8"), hashlib.sha3_256).hexdigest()
	# print(h)


def main():
	fingerprint = get_fingerprint()
	generate_hmac()
	print(fingerprint)


if __name__ == "__main__":
	main()
