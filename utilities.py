#!/usr/bin/env python3
from secrets import choice, token_bytes

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA3_256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.padding import PKCS7


class CipherContext:
	def __init__(self, password):
		self._password = password
		self._known_keys = {}

	def encrypt(self, plaintext):
		if not getattr(self, '_cipher_key', None):
			self._cipher_salt = token_bytes(32)
			self._cipher_key = derive_key(password, self._cipher_salt)
			self._known_keys[self._cipher_salt] = self._cipher_key

		# The salt (IV) can only be as large as the AES block-size.
		salt = token_bytes(AES.block_size // 8)

		padder = PKCS7(AES.block_size).padder()
		padded_data = padder.update(plaintext) + padder.finalize()

		encryptor = Cipher(AES(self._cipher_key), CBC(salt)).encryptor()
		ciphertext = encryptor.update(padded_data) + encryptor.finalize()

		return self._cipher_salt + salt + ciphertext

	def decrypt(self, ciphertext):
		cipher_salt = ciphertext[:32]
		cipher_key = self._known_keys.get(cipher_salt)

		if not cipher_key:
			cipher_key = derive_key(self._password, cipher_salt)
			self._known_keys[cipher_salt] = cipher_key

		salt = ciphertext[32:(AES.block_size // 8) + 32]
		ciphertext = ciphertext[(AES.block_size // 8) + 32:]

		decryptor = Cipher(AES(cipher_key), CBC(salt)).decryptor()
		padded_data = decryptor.update(ciphertext) + decryptor.finalize()

		unpadder = PKCS7(AES.block_size).unpadder()
		plaintext = unpadder.update(padded_data) + unpadder.finalize()

		return plaintext


class RotatingCipherContext(CipherContext):
	def generate_keys(self, variations=4):
		self._variants = {}

		for index in range(variations):
			salt = token_bytes(32)
			key = derive_key(self._password, salt)
			self._variants[salt] = key
			self._known_keys[salt] = key

	def encrypt(self, plaintext):
		if not getattr(self, '_variants', None):
			self.generate_keys()

		self._cipher_salt = choice(list(self._variants.keys()))
		self._cipher_key = self._variants[self._cipher_salt]
		return super().encrypt(plaintext)


def derive_key(password, salt):
	return Scrypt(
		salt=salt,
		length=32,
		n=2**20,
		r=8,
		p=1
	).derive(password.encode())
