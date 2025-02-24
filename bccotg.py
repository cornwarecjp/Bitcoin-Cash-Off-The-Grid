#!/usr/bin/env python3
#    bchotg.py
#    Copyright (C) 2015-2025 by CJP
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

import binascii
import decimal
import sys

from crypto import Key, SHA256, RIPEMD160
import base58
import bitcointransaction as btx



BCH = 100000000 #Satoshi


def readPrivateKey(filename):
	with open(filename, "r") as f:
		privateKey = f.read()
	privateKey = privateKey.split("\n")[0] #first line
	privateKey = privateKey.strip() #ignore whitespace
	return base58.decodeBase58Check(privateKey, 128) #PRIVKEY = 128


def getAddress(key):
	publicKeyHash = RIPEMD160(SHA256(key.getPublicKey()))
	return base58.encodeBase58Check(publicKeyHash, 0) #PUBKEY_ADDRESS = 0


def getinfo(args):
	for filename in args:
		print('----------------')
		print('Filename: ', filename)
		privateKey = readPrivateKey(filename)
		k = Key()
		k.setPrivateKey(privateKey)
		print('Public key: ', k.getPublicKey().hex())
		print('Address: ', getAddress(k))


def spend(args):
	#Load the keys
	keys = []
	for filename in args:
		privateKey = readPrivateKey(filename)
		k = Key()
		k.setPrivateKey(privateKey)
		keys.append(k)

	def getKey(question):
		for i in range(len(keys)):
			print(i+1, getAddress(keys[i]))
		i = int(input(question)) - 1
		return keys[i]

	#Ask for input information:
	inputs = []
	amounts = []
	while True:
		txid = input('Transaction ID of unspent output (Enter to stop): ')
		txid = txid.strip()
		if txid == "":
			break
		txid = binascii.unhexlify(txid)[::-1]

		vout = int(input('Output index of unspent output: '))
		k = getKey('Address of unspent output: ')
		inputs.append((txid, vout, k))
		amounts.append(int(decimal.Decimal(
			input('Amount in unspent output (BCH): ')
			) * BCH))

	totalAmount = sum(amounts)
	print('Total of amounts: %s BCH' % str(decimal.Decimal(totalAmount)/BCH))

	fee = int(decimal.Decimal(
			input('Transaction fee (BCH): ')
			) * BCH)

	destAddress = input('Destination address: ')
	destHash = base58.decodeBase58Check(destAddress, 0) #PUBKEY_ADDRESS = 0

	destAmount = totalAmount - fee

	print('Amount sent to destination: %s BCH' % str(decimal.Decimal(destAmount)/BCH))
	if destAmount < 0:
		print('Negative amount is not allowed')
		sys.exit(2)

	tx = btx.Transaction(
		tx_in = [
			btx.TxIn(x[0], x[1])
			for x in inputs
			],
		tx_out = [
			btx.TxOut(destAmount, btx.Script.standardPubKey(destHash))
			]
		)

	for i in range(len(inputs)):
		#print tx.tx_in[i].previousOutputHash.encode("hex"), tx.tx_in[i].previousOutputIndex
		key = inputs[i][2]
		address = getAddress(key)
		hash = base58.decodeBase58Check(address, 0) #PUBKEY_ADDRESS = 0
		scriptPubKey = btx.Script.standardPubKey(hash)
		tx.signInput(i, scriptPubKey, [None, key.getPublicKey()], [key], amounts[i])

	print('Serialized transaction:')
	print(tx.serialize().hex())
	print('Transaction ID:', tx.getTransactionID()[::-1].hex())


def decode(args):
	s = args[0]
	amounts = [int(decimal.Decimal(a)*BCH) for a in args[1:]]
	serialized = binascii.unhexlify(s)
	tx = btx.Transaction.deserialize(serialized)
	print('lockTime: ', tx.lockTime)
	for i in range(len(tx.tx_in)):
		tx_in = tx.tx_in[i]
		print('TxIn:')
		print('    amount: %s BCH' % str(decimal.Decimal(amounts[i])/BCH))
		print('    prevOutputHash: ', tx_in.previousOutputHash.hex())
		print('    prevOutputIndex: ', tx_in.previousOutputIndex)
		print('    sequenceNumber: 0x%08x' % tx_in.sequenceNumber)
		print('    script:')
		for e in tx_in.scriptSig.elements:
			if isinstance(e, bytes):
				s = e.hex()
			else:
				s = str(e)
			print('        ', s)
		signature, pubKey = tx_in.scriptSig.elements
		hashType = signature[-1]
		signature = signature[:-1]

		k = Key()
		k.setPublicKey(pubKey)
		address = getAddress(k)
		hash = base58.decodeBase58Check(address, 0) #PUBKEY_ADDRESS = 0
		scriptPubKey = btx.Script.standardPubKey(hash)

		sigHash = tx.getSignatureBodyHash(i, scriptPubKey, hashType, amount=amounts[i])

		print('        pubKey: ', pubKey.hex())
		print('        signature: ', signature.hex())
		print('        hashType: 0x%0x' % hashType)
		print('        address: ', address)
		print('        sigHash: ', sigHash.hex())
		print('        valid: ', k.verify(sigHash, signature))
		print('')

	for tx_out in tx.tx_out:
		print('TxOut:')
		print('    amount: %s BCH' % str(decimal.Decimal(tx_out.amount)/BCH))

		elements = tx_out.scriptPubKey.elements
		print('    script:')
		for e in elements:
			if isinstance(e, bytes):
				s = e.hex()
			else:
				s = '0x%0x' % e
			print('        ', s)

		if len(elements) == 5 and \
			elements[0:2] == [btx.OP.DUP, btx.OP.HASH160] and \
			elements[3:5] == [btx.OP.EQUALVERIFY, btx.OP.CHECKSIG] and \
			isinstance(elements[2], bytes):

			address = base58.encodeBase58Check(elements[2], 0) #PUBKEY_ADDRESS = 0
			print('    Address: ', address)
		else:
			print('    Unrecognized script type')

		print('')

	fee = sum(amounts) - sum([tx_out.amount for tx_out in tx.tx_out])
	print('Tx fee: %s BCH' % str(decimal.Decimal(fee)/BCH))



funcs = \
{
'getinfo': getinfo,
'decode': decode,
'spend': spend,
}
funcNames = list(funcs.keys())
funcNames.sort()

if len(sys.argv) < 2 or sys.argv[1] not in funcNames:
	print('Usage: %s <command> [<args>]' % sys.argv[0])
	print('Command can be one of:')
	for fn in funcNames:
		print(fn)
	sys.exit(1)

funcs[sys.argv[1]](sys.argv[2:])

