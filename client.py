from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import uuid
import getpass
import os
import requests
import base64
import hashlib


def get_fingerprint():
	mac = hex(uuid.getnode())
	name = os.environ["COMPUTERNAME"]
	username = getpass.getuser()
	serial = os.popen("wmic csproduct get uuid").read().replace("\n","").replace(" ","")  # note: only works for windows
	fingerprint = hashlib.sha3_256((mac + name + username + serial).encode("utf-8")).hexdigest()
	return fingerprint


def validate_response():
	fingerprint = get_fingerprint()
	response = requests.post("http://localhost:5000/api/verify_license", json={"fingerprint": fingerprint, "email": "test@mail.com.com", "password": "password"}).json()
	signature = response["signature"]
	message_id = response["message_id"]
	valid = response["valid"]
	with open("public_key.pem", "rb") as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
			backend=default_backend()
		)
	message = bytes(hashlib.sha3_256((str(message_id) + str(valid)).encode("utf-8")).hexdigest(), "utf-8")  # re-compute hash of id and valid
	signature = base64.b64decode(signature)
	try:
		public_key.verify(
			signature,
			message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA3_256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA3_256()
		)
		valid_signature = True  # message came from us
	except InvalidSignature:
		valid_signature = False  # message did not come from us
	return valid_signature, valid


def main():
	valid_signature, valid = validate_response()
	if valid_signature:
		print("Message came from us.")
	else:
		print("Message did not come from us.")
	if valid:
		print("Valid license information.")
	else:
		print("Invalid license information.")


if __name__ == "__main__":
	main()
