#    bitcointransaction.py
#    Copyright (C) 2014-2025 by CJP
#
#    This file is part of Bitcoin Cash Off The Grid (BCCOTG).
#
#    BCCOTG is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    BCCOTG is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with BCCOTG. If not, see <http://www.gnu.org/licenses/>.
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

import struct
import copy
from crypto import SHA256



#see https://en.bitcoin.it/wiki/Transactions
#see https://en.bitcoin.it/wiki/Protocol_specification
#see https://en.bitcoin.it/wiki/Script

def packVarInt(i):
	"""
	Bitcoin variable length integer encoding

	Arguments:
	i: int; the to-be-encoded integer value (range 0 .. 2**64-1)

	Return value:
	bytes; the variable-length encoded value

	Exceptions:
	struct.error: integer out of range
	"""

	if i < 0xfd:
		return struct.pack('B', i) #uint8_t
	elif i <= 0xffff:
		return struct.pack('B', 0xfd) + struct.pack('<H', i) #uint16_t
	elif i <= 0xffffffff:
		return struct.pack('B', 0xfe) + struct.pack('<I', i) #uint32_t
	else:
		return struct.pack('B', 0xff) + struct.pack('<Q', i) #uint64_t


def unpackVarInt(data):
	"""
	Bitcoin variable length integer decoding

	Arguments:
	bytes; the variable-length encoded value

	Return value:
	i: int; the decoded integer value

	Exceptions:
	struct.error: unexpected end of data
	"""

	firstByte = data[0] #uint8_t
	if firstByte < 0xfd:
		value = firstByte
		return value, 1
	elif firstByte == 0xfd:
		value = struct.unpack('<H', data[1:3])[0] #uint16_t
		return value, 3
	elif firstByte == 0xfe:
		value = struct.unpack('<I', data[1:5])[0] #uint32_t
		return value, 5
	elif firstByte == 0xff:
		value = struct.unpack('<Q', data[1:9])[0] #uint64_t
		return value, 9

	raise Exception("Bug detected in unpackVarInt")



class OP:
	"""
	Bitcoin script op-codes
	"""

	ZERO = 0x00
	TWO = 0x52
	RETURN = 0x6a
	DUP = 0x76
	EQUAL  = 0x87
	EQUALVERIFY = 0x88
	SHA256 = 0xa8
	HASH160 = 0xa9
	CHECKSIG = 0xac
	CHECKSIGVERIFY = 0xad
	CHECKMULTISIG = 0xae



class SIGHASH:
	"""
	Bitcoin signing sighash types
	"""

	ALL = 0x01
	FORKID = 0x40



class Script:
	"""
	A Bitcoin script.

	Attributes:
	elements: list or tuple of str and int; the elements are the
	          op-codes (int) and data items (str) that form the script.
	"""

	@staticmethod
	def standardPubKey(pubKeyHash):
		"""
		Creates a standard Bitcoin scriptPubKey ("send to Bitcoin address").
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		pubKeyHash: str; the SHA256- and RIPEMD160-hashed public key
		            (equivalent to the bitcoin address)

		Return value:
		Script; a scriptPubKey for sending funds to a standard Bitcoin address
		output.
		"""
		return Script((OP.DUP, OP.HASH160, pubKeyHash, OP.EQUALVERIFY, OP.CHECKSIG))


	@staticmethod
	def multiSigPubKey(pubKeys):
		"""
		Creates a 2-of-N multi-signature Bitcoin scriptPubKey.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		pubKeys: sequence of bytes; the public keys
		         2 <= len(pubKeys) <= 16

		Return value:
		Script; a scriptPubKey for sending funds to a 2-of-N multi-signature
		output.

		Exceptions:
		Exception: construction failed (e.g. too many / too few public keys given)
		"""

		N = len(pubKeys)
		if N > 16:
			raise Exception("Mult-sig with more than 16 public keys is not supported")
		if N < 2:
			raise Exception("Mult-sig with less than two keys is not supported")
		OP_N = OP.TWO + (N-2)

		return Script([OP.TWO] + pubKeys + [OP_N, OP.CHECKMULTISIG])


	@staticmethod
	def dataPubKey(data):
		"""
		Creates a data publishing scriptPubKey.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		data: bytes; the data to be included in the scriptPubKey (max. 40 bytes)

		Return value:
		Script; a scriptPubKey for including data in a transaction.
		"""
		return Script((OP.RETURN, data))


	@staticmethod
	def deserialize(data):
		"""
		De-serializes a Bitcoin script.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		data: bytes; the serialized script

		Return value:
		Script; the de-serialized script
		"""

		elements = []
		while len(data) > 0:
			opcode = data[0]
			data = data[1:]

			if opcode <= 0x4e:
				if opcode <= 0x4b:
					length = opcode
				elif opcode == 0x4c:
					length = struct.unpack('B', data[:1])[0]
					data = data[1:]
				elif opcode == 0x4d:
					length = struct.unpack('<H', data[:2])[0]
					data = data[2:]
				else:
					length = struct.unpack('<I', data[:4])[0]
					data = data[4:]
				elements.append(data[:length])
				data = data[length:]
			else:
				elements.append(opcode)

		return Script(elements)


	def __init__(self, elements=tuple()):
		"""
		Constructor.

		Arguments:
		elements: list or tuple of bytes and int; the elements are the
			      op-codes (int) and data items (str) that form the script.
		"""
		self.elements = elements


	def serialize(self):
		"""
		Serializes the script.

		Return value:
		bytes; the serialized script

		Exceptions:
		Exception: serialization failed
		"""
		return b''.join([self.__serializeElement(e) for e in self.elements])


	def __serializeElement(self, e):
		"""
		Serializes a single script element.

		Arguments:
		e: bytes or int; the to-be-serialized element.

		Return value:
		bytes; the serialized element.

		Exceptions:
		Exception: serialization failed
		"""

		if isinstance(e, bytes):
			if len(e) <= 0x4b:
				return struct.pack('B', len(e)) + e
			elif len(e)<= 0xff:
				return struct.pack('B', 0x4c) + struct.pack('B', len(e)) + e
			elif len(e) <= 0xffff:
				return struct.pack('B', 0x4d) + struct.pack('<H', len(e)) + e
			elif len(e) <= 0xffffffff:
				return struct.pack('B', 0x4e) + struct.pack('<I', len(e)) + e
			else:
				raise Exception('Too long data for a script item')
		elif isinstance(e, int):
			return struct.pack('B', e)
		else:
			raise Exception('Unsupported element type in script')



class TxIn:
	"""
	A Bitcoin transaction input.

	Attributes:
	previousOutputHash: str; the transaction ID of the previous output transaction.
	                    Note that the byte order is the reverse as shown in Bitcoin.
	previousOutputIndex: int; the index of the output in the previous output transaction
	scriptSig: Script; the scriptSig
	"""

	@staticmethod
	def deserialize(data):
		"""
		De-serializes a transaction input.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		data: bytes; the serialized transaction input.
		      May contain trailing bytes that are not part of the serialized
		      transaction input.

		Return value:
		Tuple, containing:
		TxIn; the de-serialized transaction input
		int; the number of bytes that has been read
		"""

		outputHash = data[:32]
		data = data[32:]

		outputIndex = struct.unpack('<I', data[:4])[0] #uint32_t
		data = data[4:]

		scriptSigLen, numBytesInLen = unpackVarInt(data)
		data = data[numBytesInLen:]

		scriptSig = Script.deserialize(data[:scriptSigLen])
		data = data[scriptSigLen:]

		sequenceNumber = struct.unpack('<I', data[:4])[0] #uint32_t

		obj = TxIn(outputHash, outputIndex, sequenceNumber)
		obj.scriptSig = scriptSig
		numBytes = 36 + numBytesInLen + scriptSigLen + 4

		return obj, numBytes


	def __init__(self, outputHash, outputIndex, sequenceNumber=0xffffffff):
		"""
		Constructor.

		Arguments:
		outputHash: bytes; the transaction ID of the previous output transaction
		outputIndex: int; the index of the output in the previous output transaction
		"""
		self.previousOutputHash = outputHash
		self.previousOutputIndex = outputIndex
		self.scriptSig = Script() #Default: no signature (to be filled in later)
		self.sequenceNumber = sequenceNumber


	def serialize(self):
		"""
		Serializes the transaction input.

		Return value:
		bytes; the serialized transaction input
		"""

		ret = self.previousOutputHash
		ret += struct.pack('<I', self.previousOutputIndex) #uint32_t
		scriptSig = self.scriptSig.serialize()
		ret += packVarInt(len(scriptSig))
		ret += scriptSig
		ret += struct.pack('<I', self.sequenceNumber) #uint32_t

		return ret



class TxOut:
	"""
	A Bitcoin transaction output.

	Attributes:
	amount: int; the amount (in Satoshi)
	scriptPubKey: Script; the scriptPubKey
	"""

	@staticmethod
	def deserialize(data):
		"""
		De-serializes a transaction output.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		data: bytes; the serialized transaction output.
		      May contain trailing bytes that are not part of the serialized
		      transaction output.

		Return value:
		Tuple, containing:
		TxOut; the de-serialized transaction output
		int; the number of bytes that has been read
		"""

		amount = struct.unpack('<Q', data[:8])[0] #uint64_t
		data = data[8:]

		scriptPubKeyLen, numBytesInLen = unpackVarInt(data)
		data = data[numBytesInLen:]

		scriptPubKey = Script.deserialize(data[:scriptPubKeyLen])

		obj = TxOut(amount, scriptPubKey)
		numBytes = 8 + numBytesInLen + scriptPubKeyLen

		return obj, numBytes


	def __init__(self, amount, scriptPubKey):
		"""
		Constructor.

		Arguments:
		amount: int; the amount (in Satoshi)
		scriptPubKey: Script; the scriptPubKey
		"""
		self.amount = amount
		self.scriptPubKey = scriptPubKey


	def serialize(self):
		"""
		Serializes the transaction output.

		Return value:
		bytes; the serialized transaction output
		"""

		ret = struct.pack('<Q', self.amount) #uint64_t
		scriptPubKey = self.scriptPubKey.serialize()
		ret += packVarInt(len(scriptPubKey))
		ret += scriptPubKey		

		return ret



class Transaction:
	"""
	A Bitcoin transaction.

	Attributes:
	tx_in: list of TxIn; the transaction inputs
	tx_out: list of TxOut; the transaction outputs
	lockTime: int; the lock time
	"""

	@staticmethod
	def deserialize(data):
		"""
		De-serializes a transaction.
		This is a static method: it can be called without having an instance,
		as an alternative to calling the constructor directly.

		Arguments:
		data: bytes; the serialized transaction.

		Return value:
		Transaction; the de-serialized transaction

		Exceptions:
		Exception: deserialization failed
		"""

		version = struct.unpack('<I', data[:4])[0] #version, uint32_t
		data = data[4:]

		if version != 2:
			raise Exception("Transaction deserialization failed: version != 2")

		num_tx_in, numBytes = unpackVarInt(data)
		data = data[numBytes:]
		tx_in = []
		for i in range(num_tx_in):
			obj, numBytes = TxIn.deserialize(data)
			data = data[numBytes:]
			tx_in.append(obj)

		num_tx_out, numBytes = unpackVarInt(data)
		data = data[numBytes:]
		tx_out = []
		for i in range(num_tx_out):
			obj, numBytes = TxOut.deserialize(data)
			data = data[numBytes:]
			tx_out.append(obj)

		#To make sure we're not accepting a transaction that has been serialized
		#in a non-standard way (e.g. containing trailing information).
		#This might be important when making/checking signatures.
		#It might be advisable anyway to re-serialize a received transaction and
		#check whether the result matches the original.
		if len(data) != 4:
			raise Exception("Transaction deserialization failed: incorrect data length")

		lockTime = struct.unpack('<I', data[:4])[0] #uint32_t

		return Transaction(tx_in, tx_out, lockTime)


	def __init__(self, tx_in, tx_out, lockTime=0):
		"""
		Constructor.

		Arguments:
		tx_in: list of TxIn; the transaction inputs
		tx_out: list of TxOut; the transaction outputs
		lockTime: int; the lock time
		"""
		self.version = 2
		self.tx_in = tx_in
		self.tx_out = tx_out
		self.lockTime = lockTime


	def serialize(self):
		"""
		Serializes the transaction.

		Return value:
		bytes; the serialized transaction
		"""

		ret = struct.pack('<I', self.version) #version, uint32_t
		ret += packVarInt(len(self.tx_in))
		for tx_in in self.tx_in:
			ret += tx_in.serialize()
		ret += packVarInt(len(self.tx_out))
		for tx_out in self.tx_out:
			ret += tx_out.serialize()
		ret += struct.pack('<I', self.lockTime) #uint32_t
		return ret


	def getSignatureBodyHash(self, index, scriptPubKey, hashType=SIGHASH.ALL+SIGHASH.FORKID, amount=None):
		"""
		Calculates the hash of properly masked serialized data of this
		transaction, for use in signing and in verification of signatures, e.g.
		those used in in OP_CHECKSIG.

		Arguments:
		index: int; the index of the transaction input to which a signature
		       applies
		scriptPubKey: Script; the scriptPubKey of the output to which the
		              signature applies
		hashType: int; the hash type (default: SIGHASH.ALL+SIGHASH.FORKID = 0x41)
		amount: int; the amount of the transaction input (default: None)

		Return value:
		bytes; the double-SHA256-hashed, masked, serialized transaction:
		this is the data that must be signed in OP_CHECKSIG (and similar)
		signatures.
		"""

		if hashType == SIGHASH.ALL:
			#https://en.bitcoin.it/wiki/OP_CHECKSIG

			#1.	the public key and the signature are popped from the stack, in that
			#	order. If the hash-type value is 0, then it is replaced by the
			#	last_byte of the signature. Then the last byte of the signature is
			#	always deleted.
			#2.	A new subscript is created from the instruction from the most
			#	recently parsed OP_CODESEPARATOR (last one in script) to the end of
			#	the script. If there is no OP_CODESEPARATOR the entire script
			#	becomes the subscript (hereby referred to as subScript)
			#3.	The sig is deleted from subScript.
			#4.	All OP_CODESEPARATORS are removed from subScript

			#Since there is no OP_CODESEPARATOR or signature in scriptPubKey:
			subScript = scriptPubKey

			#6.	A copy is made of the current transaction (hereby referred to txCopy)
			txCopy = copy.deepcopy(self)

			#7.	The scripts for all transaction inputs in txCopy are set to empty
			#	scripts (exactly 1 byte 0x00)
			for tx_in in txCopy.tx_in:
				tx_in.scriptSig = Script() #Empty (zero-byte)

			#8.	The script for the current transaction input in txCopy is set to
			#	subScript (lead in by its length as a var-integer encoded!)
			txCopy.tx_in[index].scriptSig = subScript

			#An array of bytes is constructed from the serialized txCopy appended by
			#four bytes for the hash type.
			signatureBody = txCopy.serialize() + struct.pack('<I', hashType) #uint32_t
		elif hashType == SIGHASH.FORKID + SIGHASH.ALL:
			if amount is None:
				raise Exception('Please provide input amounts for SIGHASH_FORKID hashing')

			#https://github.com/Bitcoin-UAHF/spec/blob/master/replay-protected-sighash.md

			#1. nVersion of the transaction (4-byte little endian)
			signatureBody = struct.pack('<I', self.version) #version, uint32_t

			#2. hashPrevouts (32-byte hash)
			#double SHA256 of the serialization of all input outpoints
			signatureBody += SHA256(SHA256(b''.join([
				tx_in.previousOutputHash + struct.pack('<I', tx_in.previousOutputIndex) #uint32_t
				for tx_in in self.tx_in
				])))

			#3. hashSequence (32-byte hash)
			#double SHA256 of the serialization of nSequence of all inputs
			signatureBody += SHA256(SHA256(b''.join([
				struct.pack('<I', tx_in.sequenceNumber) #uint32_t
				for tx_in in self.tx_in
				])))

			#4..7 are the input being signed (replacing the scriptSig with scriptCode + amount).

			#4. outpoint (32-byte hash + 4-byte little endian)
			#may already be contained in hashPrevouts
			signatureBody += self.tx_in[index].previousOutputHash
			signatureBody += struct.pack('<I', self.tx_in[index].previousOutputIndex) #uint32_t

			#5. scriptCode of the input (serialized as scripts inside CTxOuts)
			scriptPubKey_serialized = scriptPubKey.serialize()
			signatureBody += packVarInt(len(scriptPubKey_serialized))
			signatureBody += scriptPubKey_serialized

			#6. value of the output spent by this input (8-byte little endian)
			signatureBody += struct.pack('<Q', amount) #uint64_t

			#7. nSequence of the input (4-byte little endian)
			#may already be contained in hashSequence
			signatureBody += struct.pack('<I', self.tx_in[index].sequenceNumber) #uint32_t

			#8. hashOutputs (32-byte hash)
			#double SHA256 of the serialization of all output amounts (8-byte little endian)
			#paired up with their scriptPubKey (serialized as scripts inside CTxOuts)
			signatureBody += SHA256(SHA256(b''.join([
				tx_out.serialize()
				for tx_out in self.tx_out
				])))

			#9. nLocktime of the transaction (4-byte little endian)
			signatureBody += struct.pack('<I', self.lockTime) #uint32_t

			#10. sighash type of the signature (4-byte little endian)
			#note: in UAHF, forkID = 0
			signatureBody += struct.pack('<I', hashType) #uint32_t

		else:
			raise Exception('hash type 0x%0x not supported' % hashType)

		#This array is sha256 hashed twice,
		bodyHash = SHA256(SHA256(signatureBody))

		return bodyHash


	def signInputWithSignatures(self, index, scriptSigTemplate, signatures):
		"""
		Signs an input with the given signatures.

		Arguments:
		index: int; the index of the transaction input to which the signatures
		       apply
		scriptSigTemplate: list of bytes, int and None: a template of the scriptSig
		                   elements. Each occurrence of None will be replaced by
		                   a signature.
		signatures: list of bytes; the signatures. The number of signatures must
		            be at least the number of occurrences of None in scriptSigTemplate.
		"""

		elements = scriptSigTemplate[:]
		for sig in signatures:
			i = elements.index(None)
			elements[i] = sig

		self.tx_in[index].scriptSig = Script(elements)


	def signInput(self, index, scriptPubKey, scriptSigTemplate, privateKeys, amount=None):
		"""
		Signs an input with the given private keys.

		Arguments:
		index: int; the index of the transaction input to which the signatures
		       apply
		scriptPubKey: Script; the scriptPubKey of the output to which the
		              signature applies
		scriptSigTemplate: list of bytes, int and None: a template of the scriptSig
		                   elements. Each occurrence of None will be replaced by
		                   a signature.
		privateKeys: list of Key; the private keys. The number of keys must be
		             at least the number of occurrences of None in scriptSigTemplate.
		amount: int; the amount of the transaction input (default: None)
		"""

		hashType = SIGHASH.ALL+SIGHASH.FORKID
		bodyHash = self.getSignatureBodyHash(index, scriptPubKey, hashType, amount=amount)

		#then the public key is used to check the supplied signature against the
		#hash. The secp256k1 elliptic curve is used for the verification with
		#the given public key.

		#5.	The hashtype is removed from the last byte of the sig and stored
		#hashType = sig[-1]
		#sig = sig[:-1]
		#Here we do the inverse - add hashType:
		signatures = \
		[
			key.sign(bodyHash) + struct.pack('B', hashType) #uint8_t
			for key in privateKeys
		]

		self.signInputWithSignatures(index, scriptSigTemplate, signatures)


	def getTransactionID(self):
		"""
		Returns the transaction ID.

		Return value:
		bytes; the transaction ID. Note that the byte order is the reverse as
		shown in Bitcoin.
		"""
		return SHA256(SHA256(self.serialize())) #Note: in Bitcoin, the tx hash is shown reversed!


