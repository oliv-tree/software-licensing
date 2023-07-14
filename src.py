from bcrypt import gensalt
import pymysql
import requests
from datetime import datetime, timedelta
import re
import stripe
from flask import jsonify


stripe.api_key = ""  # TODO: get from credentials.json


def make_query(query, use_database="licensing"):  # make a query given an SQL statement
	d_b = pymysql.connect(host="localhost", user="root", passwd="", db=use_database)  # connect to DB (TODO: get from credentials.json)
	cursor = d_b.cursor()
	try:
		cursor.execute(query)
		results = cursor.fetchall()
		if results:
			results = results[0]
	except (pymysql.IntegrityError, pymysql.DataError, pymysql.err.ProgrammingError):  # catches duplicate primary key, too long, invalid SQL
		results = None
	d_b.commit()
	d_b.close()  # close connection
	return results


def send_reset_email(email, url):
	# secure!
	print(email)
	print(url)


def create_account(email, password, ph):
	# checks
	# run this code when the user buys the product
	salt = gensalt().decode("utf-8")
	hashed_password = ph.hash(salt + password)
	created = datetime.now()
	expiry = created + timedelta(days=365)
	make_query(f"INSERT INTO `users` values(NULL, \"{email}\", \"{hashed_password}\", \"{salt}\", NULL, \"{created}\", \"{expiry}\");")  # verify this worked!
	requests.post("http://localhost:5000/api/generate_reset_email", json={"email": email}, headers={"content-type": "application/json"})  # verify this worked!
	# what do we do if any of this fails?
	return True


def renew_account(email):
	# checks
	# run this code when the user buys the product
	database_data = make_query(f"SELECT `expiry` FROM `users` WHERE `email`=\"{email}\";")
	if database_data:
		current_expiry = database_data[0]
		now = datetime.now()
		if current_expiry < now:  # expired already so add 6 months from now
			expiry = now + timedelta(days=182.5)
		else:  # not expired so add 6 months to current time
			expiry = current_expiry + timedelta(days=182.5)
		make_query(f"UPDATE `users` SET `expiry`=\"{expiry}\" WHERE `email`=\"{email}\";")
	#  they should only be able to renew if they have a valid account!
	return True


def verify_captcha(captcha_response):
	valid_captcha = requests.post("https://www.google.com/recaptcha/api/siteverify", data={"secret": "", "response": captcha_response}).json()["success"]  # TODO: get from credentials.json
	return valid_captcha


def validate_email(email):
	if re.fullmatch(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", email):
		return True
	return False


def validate_password(password):
	if re.fullmatch(r".{8,30}", password):
		return True
	return False


def retrieve_stock():
	sku = "sku_GW5l0kaqvH9F9o"
	status = stripe.SKU.retrieve(sku)
	quantity = status["inventory"]["quantity"]
	return quantity


def update_stock(quantity):
	sku = "sku_GW5l0kaqvH9F9o"
	stripe.SKU.modify(sku, inventory={"quantity": quantity})


def validate_data_existence(data, fields):
	for field in fields:
		if field not in data:
			return False
	return True


def generate_response(intent, product, email, password=None):
	# Note that if your API version is before 2019-02-11, "requires_action"
	# appears as "requires_source_action".
	if intent.status == "requires_action" and intent.next_action.type == "use_stripe_sdk":
		# Tell the client to handle the action
		return jsonify({
			"requires_action": True,
			"payment_intent_client_secret": intent.client_secret,
		}), 200
	elif intent.status == "succeeded":
		# The payment didn’t need any additional actions and completed!
		if product == "license":
			print(email, password)
			# create_account(email, password, ph)
			# print(f"create account {email} {password}")
			# catch errors and ...?
		else:
			print(email)
			# renew_account(email)
			# print(f"renew account {email}")
			# catch errors and ...?
		return jsonify({"success": True}), 200
	else:
		# Invalid status
		return jsonify({"error": "Invalid payment session"}), 500


def retrieve_expiry(email):
	database_data = make_query(f"SELECT `expiry` FROM `users` WHERE `email`=\"{email}\";")
	if database_data:
		user_expiry = database_data[0].strftime("%d/%m/%Y")
	else:
		user_expiry = None
	return user_expiry
