from qrcode import QRCode


_CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _parse_http(link:str) -> str:
	return link.replace(" ", "%20")


def _algo_name(algo) -> str:
	return algo if isinstance(algo, str) else algo.__name__


def _convert_from_secret(secret:str) -> str:
	def _lambda(value:str) -> str:
		val = bin(_CHARSET.find(value)).replace("0b", "")
		return val.zfill(5)

	binary_string = "".join([_lambda(i) for i in secret])

	new_string = ""
	for i in range(0, len(binary_string), 4):
		new_string += hex(int(binary_string[i:i+4], 2))[2:]
	return new_string


def _hmac(hexkey:str, msg:str, algo="sha1"):
	from hmac import new
	from binascii import unhexlify

	key = unhexlify(hexkey)
	msg = unhexlify(msg)

	return new(key, msg, algo).hexdigest()


def _gen_htop_value(hash_value, length:int = 6):
	hmac_result = [int(hash_value[_hex:_hex+2], 16) for _hex in range(0, len(hash_value), 2)]

	offset = hmac_result[len(hmac_result)-1] & 0xf
	code = int(
		(hmac_result[offset] & 0x7f) << 24 |
		(hmac_result[offset+1] & 0xff) << 16 |
		(hmac_result[offset+2] & 0xff) << 8 |
		(hmac_result[offset+3] & 0xff)
	)

	return code % (10 ** length)


def generate_token(key:str, time:float | int = None, length:int = 6, time_interval:int = 30, algo="sha1") -> str:
	"""
	:param str key: The key for the TOTP
	:param int|float|None time: The time the code should be generated. This should only be set if the current unix time is not the wanted time.
	:param int length: The number of digits in the code. Default is 6.
	:param int time_interval: The interval between new codes. Default is 30.
	:param algo: The hash algorithm, imported from hashlib, used to generate the code. Default is sha1.

	Example:
		>>> print(generate_token("ACAHAACAAJGILAOC"))  # Current UNIX time is 1,674,064,199.9493444
		>>> 938585
	"""
	from time import time as time_func
	from math import floor

	# Pad the key if necessary
	from hashlib import sha256, sha512
	if _algo_name(algo) == "sha256":
		key = key + key[:12]
	elif _algo_name(algo) == "sha512":
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


class TOTP:
	def __init__(self, key:str, length:int = 6, time_interval:int = 30, algo="sha1"):
		"""
		:param str key: The key for the TOTP
		:param int length: The number of digits in the code. Default is 6.
		:param int time_interval: The interval between new codes. Default is 30.
		:param algo: The hash algorithm, imported from hashlib, used to generate the code. Default is sha1.

		Example:
			>>> otp = TOTP("ACAHAACAAJGILAOC")
			>>> otp.generate()  # at current UNIX time 1,674,064,341.962709
			>>> '437342'
			>>> otp.generate()  # at current UNIX time 1,674,064,357.8367786
			>>> '055711'
		"""
		self.key = key
		self.length = length
		self.time_interval = time_interval
		self.algo = algo

	def generate(self, time=None) -> str:
		"""
		Generates the TOTP at the given time with all the saved parameters.

		:param int|float|None time: The time the code should be generated. This should only be set if the current unix time is not the wanted time.
		"""
		return generate_token(self.key, time, self.length, self.time_interval, self.algo)

	def link(self, issuer:str, user:str, icon:str=None, add_default_args=False) -> str:
		"""
		Creates the link that is scanned into a TOTP generator app. https://www1.auth.iij.jp/smartkey/en/uri_v1.html

		:param str issuer: The name of the issuer of the TOTP, usually the application/company name.
		:param str user: The username of the person the TOTP is issued to.
		:param str|None icon: String pointing to the display icon.
		"""
		algo = self.algo if isinstance(self.algo, str) else self.algo.__name__

		if add_default_args:
			link = f"otpauth://totp/{issuer}:{user}?secret={self.key}&issuer={issuer}&Algorithm={algo}&digits={self.length}&period={self.time_interval}"
		else:
			link = f"otpauth://totp/{issuer}:{user}?secret={self.key}&issuer={issuer}"
			if algo.lower() != "sha1":
				link += f"&Algorithm={algo}"
			if len(self) != 6:
				link += f"&digits={self.length}"
			if self.time_interval != 30:
				f"period={self.time_interval}"
		if icon is not None:
			link += f"&icon={icon}"
		return _parse_http(link)

	def qr(self, issuer:str, user:str, icon:str=None, save:str=None, **kwargs) -> QRCode | None:
		"""
		Creates a QR that can be scanned into a TOTP generator app. https://www1.auth.iij.jp/smartkey/en/uri_v1.html
		Any kwarg given to qr.make_image can be given to this function.

		:param str issuer: The name of the issuer of the TOTP, usually the application/company name.
		:param str user: The username of the person the TOTP is issued to.
		:param str|None icon: String pointing to the display icon.
		:param str|None save: The file location the QR code should be saved to. If save is not given, the function will return the QRCode before qr.make_image is called.
		:param str|Color fill: The fill color of the QR code. Default is black (#000000).
		:param str|Color back: The back color of the QR code. Default is white (#ffffff).
		:param bool fit: If the image should be fitted or not. Default is True.
		:param int version: The version of the qrcode. Default is 1.
		"""
		from qrcode import constants
		from colors import Color, Colors, convert_color

		colors = Colors()
		qr = QRCode(
			version=kwargs.get("version", 1),
			error_correction=kwargs.get("error_correction", constants.ERROR_CORRECT_M),
			box_size=kwargs.get("box_size", 15),
			border=kwargs.get("border", 5)
		)

		qr.add_data(self.link(issuer, user, icon,
							  add_default_args=kwargs.get("add_default_args", False)))
		qr.make(fit=kwargs.get("fit", True))

		if save is None:
			return qr

		back = kwargs.get("back", Color(255, 255, 255, 0))
		if back != "transparent":
			back = convert_color(back)

		img = qr.make_image(
			fill_color=convert_color(kwargs.get("fill", colors.BLACK)),
			back_color=back,
			**kwargs
		)

		img.save(save)

	def styled_qr(self, issuer:str, user:str, save:str, icon:str=None, **kwargs) -> None:
		"""
		Creates a default styled QR that can be scanned into a TOTP generator app. https://www1.auth.iij.jp/smartkey/en/uri_v1.html

		:param str issuer: The name of the issuer of the TOTP, usually the application/company name.
		:param str user: The username of the person the TOTP is issued to.
		:param str|None icon: String pointing to the display icon.
		:param str save: The file location the QR code should be saved to.
		:param str|Color fill: The fill color of the QR code. Default is black (#000000).
		:param str|Color back: The back color of the QR code. Default is white (#ffffff).
		:param bool fit: If the image should be fitted or not. Default is True.
		:param int version: The version of the qrcode. Default is 1.
		"""
		from qrcode.image.styledpil import StyledPilImage
		from qrcode.image.styles.moduledrawers import RoundedModuleDrawer
		from qrcode.image.styles.colormasks import RadialGradiantColorMask

		self.qr(issuer, user, save=save, icon=icon,
				image_factory=StyledPilImage, module_drawer=RoundedModuleDrawer(),
				color_mask=RadialGradiantColorMask(back_color=(255,255,255, 0), center_color=(0,0,0,255), edge_color=(0,0,255,255)),
				**kwargs)


	# region Properties
	@property
	def key(self) -> str:
		return self._key

	@key.setter
	def key(self, key:str):
		if not isinstance(key, str):
			key = str(key)
		self._key = key

	@property
	def length(self) -> int:
		return self._length

	@length.setter
	def length(self, length:int):
		if not isinstance(length, int):
			length = int(length)
		self._length = length

	def __len__(self):
		return self._length

	@property
	def time_interval(self) -> int:
		return self._time_interval

	@time_interval.setter
	def time_interval(self, time_interval:int):
		if not isinstance(time_interval, int):
			time_interval = int(time_interval)
		if time_interval <= 0:
			raise ValueError("The time_interval (period) must be a positive amount of time.")
		self._time_interval = time_interval

	@property
	def algo(self):
		return self._algo

	@algo.setter
	def algo(self, algo):
		if algo is None and not hasattr(algo, "__call__") and not isinstance(algo, str):
			raise ValueError("The algorithm for a TOTP object must be from the hashlib library.")
		from hashlib import algorithms_available
		if _algo_name(algo) not in algorithms_available:
			raise ValueError("The algorithm must be from the hashlib library.")
		self._algo = algo
	# endregion
