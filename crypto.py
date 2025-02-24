#    crypto.py
#    Copyright (C) 2009-2013 by the Bitcoin developers
#    Copyright (C) 2013-2025 by CJP
#
#    This file is part of Bitcoin Cash Off The Grid (BCHOTG).
#
#    BCHOTG is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    BCHOTG is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with BCHOTG. If not, see <http://www.gnu.org/licenses/>.
#
#    Additional permission under GNU GPL version 3 section 7
#
#    If you modify this Program, or any covered work, by linking or combining it
#    with the OpenSSL library (or a modified version of that library),
#    containing parts covered by the terms of the OpenSSL License and the SSLeay
#    License, the licensors of this Program grant you additional permission to
#    convey the resulting work. Corresponding Source for a non-source form of
#    such a combination shall include the source code for the parts of the
#    OpenSSL library used as well as that of the covered work.

import hashlib

import secp256k1



def SHA256(data):
	"""
	Calculate the SHA256 hash of given data

	Arguments:
	data : bytes; the data of which to calculate the SHA256 hash

	Return value:
	bytes; the SHA256 hash.
	"""
	return hashlib.sha256(data).digest()


def RIPEMD160(data):
	"""
	Calculate the RIPEMD160 hash of given data

	Arguments:
	data : bytes; the data of which to calculate the RIPEMD160 hash

	Return value:
	bytes; the RIPEMD160 hash.
	"""
	return hashlib.new('ripemd160', data).digest()


class Key:
	"""
	An ECDSA key object.

	Contains either no keys, a public key or a public/private key pair.
	Supports both "compressed" and "non-compressed" public keys, in the same way
	as Bitcoin.
	"""

	def __init__(self):
		"""
		Constructor.
		The constructed object does not contain any key data.
		"""

		self.privKey = None
		self.pubKey = None
		self.compressed = None


	def setPublicKey(self, key):
		"""
		Sets a public key.
		Previous key data (if any) is discarded.

		Arguments:
		key: bytes; the public key data
		     Note: should be 33 bytes for compressed public keys, or 65 bytes
		     for non-compressed public keys.

		Exceptions:
		Exception: setting the key failed
		"""

		self.privKey = None
		self.pubKey = secp256k1.PublicKey(key, raw=True)
		self.compressed = len(key) == 33


	def getPublicKey(self):
		"""
		Gets a public key.

		Return value:
		bytes; the public key data.

		Exceptions:
		Exception: getting the key failed
		"""

		if self.pubKey is None:
			raise Exception('Public key is not available')

		return self.pubKey.serialize(compressed=self.compressed)


	def setPrivateKey(self, key):
		"""
		Sets a private key.
		Previous key data (if any) is discarded.

		Arguments:
		key: bytes; the private key data
		     Note: should be 33 bytes for compressed public keys, or 32 bytes
		     for non-compressed public keys.

		Exceptions:
		Exception: setting the key failed
		"""

		self.compressed = len(key) == 33
		self.privKey = secp256k1.PrivateKey(key, raw=True)
		self.pubKey = self.privKey.pubkey


	def getPrivateKey(self):
		"""
		Gets a private key.

		Return value:
		bytes; the private key data.

		Exceptions:
		Exception: getting the key failed
		"""

		if self.privKey is None:
			raise Exception('Private key is not available')

		return self.privKey.serialize()


	def sign(self, data):
		"""
		Sign the given data
		Note: private key must be available.

		Arguments:
		data : bytes; the data to be signed.

		Return value:
		bytes; the signature.

		Exceptions:
		Exception: signing failed
		"""

		if self.privKey is None:
			raise Exception('Private key is not available')

		sig = self.privKey.ecdsa_sign(data, raw=True)
		return self.privKey.ecdsa_serialize(sig)


	def verify(self, data, signature):
		"""
		Verify the given signature.
		Note: public key must be available.

		Arguments:
		data : bytes; the data to which the signature applies.
		signature : bytes; the signature.

		Return value:
		bool; indicates whether the signature is correct (True) or not (False)

		Exceptions:
		Exception: signature verification failed
		"""

		if self.pubKey is None:
			raise Exception('Public key is not available')

		sig = self.pubKey.ecdsa_deserialize(signature)
		return self.pubKey.ecdsa_verify(data, sig, raw=True)

