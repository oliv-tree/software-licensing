from flask import render_template, Flask, jsonify, redirect, request, url_for, make_response, session, abort
import jwt
from datetime import datetime, timedelta
import hashlib
from urllib import parse
from argon2 import PasswordHasher, exceptions
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode
import src
import stripe
from stripe.error import InvalidRequestError


app = Flask(__name__)
app.config["SECRET_KEY"] = b""  # TODO: get from credentials.json

ph = PasswordHasher()
stripe.api_key = ""  # TODO: get from credentials.json

""" GET: home, faq """


@app.route("/", methods=["GET"])
def load_homepage():
	if src.retrieve_stock() > 0:
		in_stock = True
	else:
		in_stock = False
	return render_template("index.html", in_stock=in_stock)


@app.route("/faq", methods=["GET"])
def load_faq():
	if src.retrieve_stock() > 0:
		in_stock = True
	else:
		in_stock = False
	return render_template("faq.html", in_stock=in_stock)


@app.route("/help", methods=["GET"])
def load_help():
	if src.retrieve_stock() > 0:
		in_stock = True
	else:
		in_stock = False
	return render_template("help.html", in_stock=in_stock)


""" GET/POST: login, initiate reset password, reset password, log out """


@app.route("/initiate_reset_password", methods=["GET"])
def initiate_reset_password():
	data = request.args
	if src.validate_data_existence(data, ["message"]):
		message = data["message"]
	else:
		message = ""
	return render_template("initiate_reset.html", message=message)


@app.route("/reset_password", methods=["GET"])
def get_reset_password():
	data = request.args
	if src.validate_data_existence(data, ["token", "user_id"]):
		token = data["token"]
		user_id = data["user_id"]
		if src.validate_data_existence(data, ["message"]):
			message = data["message"]
		else:
			message = ""
		return render_template("reset_password.html", user_id=user_id, token=token, message=message)
	elif src.validate_data_existence(data, ["message"]):
		message = data["message"]
	else:
		message = ""
	return render_template("reset_password.html", message=message)


@app.route("/logout", methods=["GET"])
def load_logout():
	session.pop("email", None)
	return redirect(url_for("load_homepage"))


@app.route("/login", methods=["GET", "POST"])
def load_login():
	if "email" in session:
		return redirect(url_for("load_homepage"))
	else:
		if request.method == "POST":
			data = request.form
			if src.validate_data_existence(data, ["email", "password", "g-recaptcha-response"]):
				captcha_response = data["g-recaptcha-response"]
				if src.verify_captcha(captcha_response):
					email = data["email"]
					password = data["password"]
					if src.validate_email(email) and src.validate_password(password):
						database_data = src.make_query(f"SELECT `password`, `salt` FROM `users` WHERE `email`=\"{email}\";")
						if database_data:
							database_password = database_data[0]
							salt = database_data[1]
							try:
								ph.verify(database_password, salt + password)
								session["email"] = email
								return redirect(url_for("load_homepage"))
							except exceptions.VerifyMismatchError:
								message = "Invalid email or password"
						else:
							message = "Invalid email or password"
					else:
						message = "Invalid email or password format"
				else:
					message = "Fill out captcha"
			else:
				message = "Invalid form"
			return render_template("login.html", message=message)
		else:
			return render_template("login.html")


""" POST: reset password """


@app.route("/api/generate_reset_email", methods=["POST"])
def generate_reset_email():
	# POST to this this when user clicks "reset password" button - on website or app?
	data = request.form
	if src.validate_data_existence(data, ["email", "g-recaptcha-response"]):
		captcha_response = data["g-recaptcha-response"]
		if src.verify_captcha(captcha_response):
			message = "if this email exists, email has been sent"
			email = data["email"]
			if src.validate_email(email):
				database_data = src.make_query(f"SELECT `user_id`, `password`, `created` FROM `users` WHERE `email`=\"{email}\";")
				if database_data:
					user_id = database_data[0]
					hash = database_data[1]
					date = datetime.strftime(database_data[2], "%Y-%m-%d %H:%M:%S.%f")
					secret = hashlib.sha3_256((date + hash).encode("utf-8")).hexdigest()
					token = jwt.encode({"expiry": str(datetime.now() + timedelta(hours=1))}, secret, algorithm="HS256")  # expires after 1hr
					params = {"token": token, "user_id": user_id}
					url = f"localhost:5000/reset_password?{parse.urlencode(params)}"
					src.send_reset_email(email, url)
			else:
				message = "invalid email format"
		else:
			message = "fill out captcha"
	else:
		message = "invalid form"
	return redirect(url_for("initiate_reset_password", message=message))


@app.route("/api/reset_password", methods=["POST"])
def api_reset_password():
	# secret_key = ""
	data = request.form
	if src.validate_data_existence(data, ["g-recaptcha-response", "token", "user_id", "password"]):
		captcha_response = data["g-recaptcha-response"]
		user_id = data["user_id"]
		token = data["token"]
		if src.verify_captcha(captcha_response):
			password = data["password"]
			if src.validate_password(password):
				database_data = src.make_query(f"SELECT `password`, `salt`, `created` FROM `users` WHERE `user_id`=\"{user_id}\";")
				if database_data:
					hash = database_data[0]
					salt = database_data[1]
					date = datetime.strftime(database_data[2], "%Y-%m-%d %H:%M:%S.%f")
					secret = hashlib.sha3_256((date + hash).encode("utf-8")).hexdigest()
					try:
						payload = jwt.decode(token, secret, algorithm="HS256")
						expiry = datetime.strptime(payload["expiry"], "%Y-%m-%d %H:%M:%S.%f")
						if datetime.now() < expiry:
							message = "success"
							new_hash = ph.hash(salt + password)
							src.make_query(f"UPDATE `users` SET `password` = \"{new_hash}\" WHERE `user_id`=\"{user_id}\";")
						else:
							message = "token expired"
					except (jwt.exceptions.InvalidSignatureError, jwt.exceptions.DecodeError):
						message = "invalid token"
				else:
					message = "invalid token"  # incorrect user ID

			else:
				message = "invalid password format"
		else:
			message = "fill out captcha"
	else:
		message = "invalid form"
	return redirect(url_for("get_reset_password", message=message))


""" GET/POST: license, renewal, status """


@app.route("/password", methods=["GET"])
def load_purchase_license():
	if "email" in session:
		return redirect(url_for("load_homepage"))
	else:
		stock = src.retrieve_stock()
		if stock > 0:
			question = "What is the URL of the most viewed YouTube video?"
			data = request.args
			if src.validate_data_existence(data, ["message"]):
				message = data["message"]
				return render_template("password.html", question=question, message=message)
			# is it okay to have methods = get and post for same url?
			return render_template("password.html", question=question)
		else:
			return redirect(url_for("load_homepage"))


@app.route("/purchase/license", methods=["GET", "POST"])
def api_password():
	if request.method == "POST":
		data = request.form
		cookies = request.cookies
		if src.validate_data_existence(cookies, ["password", "answer"]):  # already got password
			purchase_password_hash = cookies["password"]
			purchase_answer_hash = cookies["answer"]
			if purchase_password_hash == hashlib.sha3_256(
				"thispasswordsucks".encode("utf-8")).hexdigest() and purchase_answer_hash == hashlib.sha3_256("https://www.youtube.com/watch?v=kJQP7kiw5Fk".encode("utf-8")).hexdigest():
				stock = src.retrieve_stock()
				if stock > 0:
					return render_template("purchase_license.html")
				else:
					message = "out of stock"
			else:
				message = "invalid password or answer"
		else:
			if src.validate_data_existence(data, ["password", "answer", "g-recaptcha-response"]):
				captcha_response = data["g-recaptcha-response"]
				if src.verify_captcha(captcha_response):
					purchase_password = data["password"]
					purchase_answer = data["answer"]
					stock = src.retrieve_stock()
					if stock > 0:
						if purchase_password == "thispasswordsucks" and purchase_answer == "https://www.youtube.com/watch?v=kJQP7kiw5Fk":  # make this central
							resp = make_response(render_template("purchase_license.html"))
							purchase_password_hash = hashlib.sha3_256(purchase_password.encode("utf-8")).hexdigest()
							purchase_answer_hash = hashlib.sha3_256(purchase_answer.encode("utf-8")).hexdigest()
							resp.set_cookie("password", purchase_password_hash)
							resp.set_cookie("answer", purchase_answer_hash)
							return resp
						else:
							message = "invalid password or answer"
					else:
						message = "out of stock"
				else:
					message = "fill out captcha"
			else:
				message = "invalid form"
	else:
		cookies = request.cookies
		if src.validate_data_existence(cookies, ["password", "answer"]):
			purchase_password_hash = cookies["password"]
			purchase_answer_hash = cookies["answer"]
			if purchase_password_hash == hashlib.sha3_256(
				"thispasswordsucks".encode("utf-8")).hexdigest() and purchase_answer_hash == hashlib.sha3_256(
				"https://www.youtube.com/watch?v=kJQP7kiw5Fk".encode("utf-8")).hexdigest():
				return render_template("purchase_license.html")
			else:
				message = "invalid password or answer"
		else:
			message = ""
	return redirect(url_for("load_purchase_license", message=message))


@app.route("/purchase/renewal", methods=["GET"])
def load_purchase_renewal():
	if "email" in session:
		return render_template("purchase_renewal.html")
	else:
		return redirect(url_for("load_homepage"))  # tell them?


@app.route("/status", methods=["GET"])
def load_status():
	data = request.args
	if src.validate_data_existence(data, ["product"]):
		product = data["product"]
		if product == "license":
			message = "Thank you. Your order of <span style=\"font-weight: 700\">VERTIGO 1 Year License</span> was successful."
		elif product == "renewal":
			message = "Thank you. Your order of <span style=\"font-weight: 700\">VERTIGO 6 month renewal</span> was successful."
		else:
			return redirect(url_for("load_homepage"))
	else:
		return redirect(url_for("load_homepage"))
	return render_template("status.html", message=message)


""" POST: license, renewal, verify """


@app.route("/api/purchase/license", methods=["POST"])
def api_purchase_license():
	# check if they already exist!
	# they can just POST here even if they didn"t fill out the password! - check our cookie stuff works
	cookies = request.cookies
	if src.validate_data_existence(cookies, ["password"]):
		purchase_password_hash = cookies["password"]
		if purchase_password_hash == hashlib.sha3_256("thispasswordsucks".encode("utf-8")).hexdigest():
			data = request.get_json()
			intent = None
			if src.validate_data_existence(data, ["email", "password", "g-recaptcha-response"]):
				captcha_response = data["g-recaptcha-response"]
				if src.verify_captcha(captcha_response):
					email = data["email"]
					password = data["password"]
					if src.validate_email(email) and src.validate_password(password):
						database_data = src.make_query(f"SELECT `user_id` FROM `users` WHERE `email`=\"{email}\";")
						if database_data:
							return jsonify({"error": "you already have a license"}), 200
						else:
							try:
								if "payment_method_id" in data:
									# Create the PaymentIntent
									quantity = src.retrieve_stock()
									if quantity > 0:
										intent = stripe.PaymentIntent.create(
											payment_method=data["payment_method_id"],
											amount=10000,
											currency="gbp",
											confirmation_method="manual",
											confirm=True,
											description="VERTIGO 1 YEAR LICENSE",
											receipt_email=email,
										)
									else:
										return jsonify({"error": "out of stock"}), 200
								elif "payment_intent_id" in data:
									quantity = src.retrieve_stock()
									if quantity > 0:
										src.update_stock(quantity - 1)
										intent = stripe.PaymentIntent.confirm(data["payment_intent_id"])
									# timing errors could fuck us here! ATOMICITY!
									else:
										return jsonify({"error": "out of stock"}), 200
							except stripe.error.CardError as e:
								# Display error on client
								return jsonify({"error": e.user_message}), 200
							product = "license"
							return src.generate_response(intent, product, email, password)
					else:
						return jsonify({"error": "invalid email or password"}), 200
				else:
					return jsonify({"error": "fill out captcha"}), 200
			else:
				return jsonify({"error": "invalid form"}), 200
	return redirect(url_for("load_purchase_license", message="invalid password"))


@app.route("/api/purchase/renewal", methods=["POST"])
def api_purchase_renewal():
	if "email" in session:
		data = request.get_json()
		intent = None
		if src.validate_data_existence(data, ["email", "g-recaptcha-response"]):
			captcha_response = data["g-recaptcha-response"]
			if src.verify_captcha(captcha_response):
				email = session["email"]
				if src.validate_email(email):
					if email in ["test171910109@gmail.com", "test1810101209@gmail.com"]:  # check if in "DB"
						try:
							if src.validate_data_existence(data, ["payment_method_id"]):
								# Create the PaymentIntent
								intent = stripe.PaymentIntent.create(
									payment_method=data["payment_method_id"],
									amount=2500,
									currency="gbp",
									confirmation_method="manual",
									confirm=True,
									description="VERTIGO 6 MONTH RENEWAL",
									receipt_email=email,
								)
							elif src.validate_data_existence(data, ["payment_intent_id"]):
								intent = stripe.PaymentIntent.confirm(data["payment_intent_id"])
						except stripe.error.CardError as e:
							# Display error on client
							return jsonify({"error": e.user_message}), 200
						product = "renewal"
						return src.generate_response(intent, product, email)
					else:
						return jsonify({"error": "please <a href=\"license\" style=\"color: #bbb\">purchase a license</a> before attempting to renew"}), 200
				else:
					return jsonify({"error": "invalid email format"}), 200
			else:
				return jsonify({"error": "fill out captcha"}), 200
		else:
			return jsonify({"error": "invalid form"}), 200
	else:
		return jsonify({"error": "please <a href=\"license\" style=\"color\": #bbb\">purchase a license</a> before attempting to renew"}), 200


@app.route("/api/verify_license", methods=["POST"])
def verify_license():
	data = request.get_json()
	message_id = uuid.uuid1()
	if src.validate_data_existence(data, ["fingerprint", "email", "password"]):
		email = data["email"]
		password = data["password"]
		if src.validate_email(email) and src.validate_password(password):
			database_data = src.make_query(f"SELECT `password`, `salt`, `fingerprint`, `expiry` FROM `users` WHERE `email` = \"{email}\";")
			if database_data:
				database_password = database_data[0]
				salt = database_data[1]
				database_fingerprint = database_data[2]
				expiry = database_data[3]
				if expiry < datetime.now():
					valid = False  # expired - should probably tell them this. maybe "status": "valid"|"invalid"|"expired" instead of "valid": True|False
				else:
					try:
						ph.verify(database_password, salt + password)
						fingerprint = data["fingerprint"]
						if database_fingerprint is None:
							src.make_query(f"UPDATE `users` SET `fingerprint`=\"{fingerprint}\";")
							valid = True
						elif fingerprint == database_fingerprint:
							valid = True
						else:
							valid = False
					except exceptions.VerifyMismatchError:
						valid = False
			else:
				valid = False
		else:
			valid = False
	else:
		valid = False
	with open("private_key.pem", "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)
	message = bytes(hashlib.sha3_256((str(message_id) + str(valid)).encode("utf-8")).hexdigest(), "utf-8")
	signature = private_key.sign(
		message,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA3_256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA3_256()
	)
	signature = str(b64encode(signature), "utf-8")
	return jsonify({"valid": valid, "message_id": message_id, "signature": signature})


""" GET: dashboard, reset device, change password """


@app.route("/dashboard", methods=["GET"])
def load_dashboard():
	if "email" in session:
		if src.retrieve_stock() > 0:
			in_stock = True
		else:
			in_stock = False
		user_expiry = src.retrieve_expiry(session["email"])
		return render_template("dashboard.html", in_stock=in_stock, user_email=session["email"], user_expiry=user_expiry)  # get expiry from DB
	else:
		return redirect(url_for("load_homepage"))


@app.route("/reset_device", methods=["GET"])
def get_reset_fingerprint():
	if "email" in session:
		data = request.args
		if src.validate_data_existence(data, ["message"]):
			message = data["message"]
		else:
			message = ""
		return render_template("reset_device.html", message=message)
	else:
		return redirect(url_for("load_homepage"))


""" POST: reset device, change password """


@app.route("/api/reset_fingerprint", methods=["POST"])
def reset_fingerprint():
	# POST to this this when user clicks "reset device" button - on website or app?
	data = request.form
	if src.validate_data_existence(data, ["email", "password", "g-recaptcha-response"]):
		captcha_response = data["g-recaptcha-response"]
		if src.verify_captcha(captcha_response):
			email = data["email"]
			password = data["password"]
			if src.validate_email(email) and src.validate_password(password):
				database_data = src.make_query(f"SELECT `password`, `salt` FROM `users` WHERE `email`=\"{email}\";")
				if database_data:
					database_password = database_data[0]
					salt = database_data[1]
					try:
						ph.verify(database_password, salt + password)
						src.make_query(f"UPDATE `users` SET `fingerprint`=NULL WHERE `email`=\"{email}\";")
						message = "success"
					except exceptions.VerifyMismatchError:
						message = "invalid email or password"
				else:
					message = "invalid email or password"
			else:
				message = "invalid email or password format"
		else:
			message = "fill out captcha"
	else:
		message = "invalid form"
	return redirect(url_for("get_reset_fingerprint", message=message))


@app.route("/api/change_password", methods=["POST"])
def api_change_password():
	# get email from session, fix all this - returning to wrong place
	data = request.form
	if src.validate_data_existence(data, ["email", "password", "new_password", "g-recaptcha-response"]):
		captcha_response = data["g-recaptcha-response"]
		if src.verify_captcha(captcha_response):
			email = data["email"]
			password = data["password"]
			new_password = data["new_password"]
			if src.validate_email(email) and src.validate_password(password) and src.validate_password(new_password):
				database_data = src.make_query(f"SELECT `password`, `salt` FROM `users` WHERE `email`=\"{email}\";")
				if database_data:
					database_password = database_data[0]
					salt = database_data[1]
					try:
						ph.verify(database_password, salt + password)
						hashed_password = ph.hash(salt + new_password)
						src.make_query(f"UPDATE `users` SET `password`=\"{hashed_password}\" WHERE `email`=\"{email}\";")
						message = "success"
					except exceptions.VerifyMismatchError:
						message = "invalid email or password"
				else:
					message = "invalid email or password"
			else:
				message = "invalid email or password"
		else:
			message = "fill out captcha"
	else:
		message = "invalid form"
	return redirect(url_for("get_change_password", message=message))


def main():
	app.run(debug=True)


if __name__ == "__main__":
	main()
