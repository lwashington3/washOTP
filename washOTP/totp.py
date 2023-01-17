_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _convert_from_secret(secret:str) -> str:
	def _lambda(value:str) -> str:
		val = bin(_CHARSET.find(value)).replace("0b", "")
		return val.zfill(5)

	binary_string = "".join([_lambda(i) for i in secret])

	new_string = ""
	for i in range(0, len(binary_string), 4):
		new_string += hex(int(binary_string[i:i+4], 2))[2:]
	return new_string


def _hmac(key:str, msg:str, algo=None):
	if algo is None:
		from hashlib import sha1
		algo = sha1
	from hmac import new
	from binascii import unhexlify

	key = unhexlify(key)
	msg = unhexlify(msg)

	return new(key, msg, algo).hexdigest()


def _gen_htop_value(hash_value, length:int=6):
	hmac_result = [int(hash_value[_hex:_hex+2], 16) for _hex in range(0, len(hash_value), 2)]

	offset = hmac_result[len(hmac_result)-1] & 0xf
	code = int(
		(hmac_result[offset] & 0x7f) << 24 |
		(hmac_result[offset+1] & 0xff) << 16 |
		(hmac_result[offset+2] & 0xff) << 8 |
		(hmac_result[offset+3] & 0xff) << 0
	)

	return code % (10 ** length)


def generate_token(key:str, time:float|int=None, length:int=6, time_interval:int=30, algo=None) -> str:
	"""
	:param str key: The key for the TOTP
	:param int|float|None time: The time the code should be generated. This should only be set if the current unix time is not the wanted time.
	:param int length: The number of digits in the code. Default is 6.
	:param int time_interval: The interval between new codes. Default is 30.
	:param algo: The hash algorithm, imported from hashlib, used to generate the code. Default is sha1.
	"""
	from time import time as time_func
	from math import floor

	if algo is None:
		from hashlib import sha1
		algo = sha1

	# Pad the key if necessary
	from hashlib import sha256, sha512
	if algo == sha256:
		key = key + key[:12]
	elif algo == sha512:
		key = key + key + key + key[:4]

	# Get the current unix timestamp if one isn't given
	if time is None:
		time = floor(time_func())
	elif time < 0:
		time = floor(time_func()) + time

	count = int(floor(time / time_interval))
	convert = _convert_from_secret(key)

	# Generate a normal HOTP token
	_hex = hex(count)[2:].zfill(16)
	output = _hmac(str(convert), str(_hex))  # Convert is the hexkey argument in the cmd prompt, which makes it the key arg here.

	code = _gen_htop_value(output, length)
	code = str(code).zfill(length)
	return code[-length:]
