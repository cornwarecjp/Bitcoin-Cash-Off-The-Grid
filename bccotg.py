#!/usr/bin/env python
#    bccotg.py
#    Copyright (C) 2015-2017 by CJP
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

import binascii
import decimal
import sys

from crypto import Key, SHA256, RIPEMD160
import base58
import bitcointransaction as btx



BCC = 100000000 #Satoshi


def readPrivateKey(filename):
	with open(filename, "rb") as f:
		privateKey = f.read()
	privateKey = privateKey.split("\n")[0] #first line
	privateKey = privateKey.strip() #ignore whitespace
	return base58.decodeBase58Check(privateKey, 128) #PRIVKEY = 128


def getAddress(key):
	publicKeyHash = RIPEMD160(SHA256(key.getPublicKey()))
	return base58.encodeBase58Check(publicKeyHash, 0) #PUBKEY_ADDRESS = 0


def getinfo(args):
	for filename in args:
		print "----------------"
		print "Filename: ", filename
		privateKey = readPrivateKey(filename)
		k = Key()
		k.setPrivateKey(privateKey)
		print "Public key: ", k.getPublicKey().encode("hex")
		print "Address: ", getAddress(k)


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
			print i+1, getAddress(keys[i])
		i = int(raw_input(question)) - 1
		return keys[i]

	#Ask for input information:
	inputs = []
	amounts = []
	while True:
		txid = raw_input("Transaction ID of unspent output (Enter to stop): ")
		txid = txid.strip()
		if txid == "":
			break
		txid = binascii.unhexlify(txid)[::-1]

		vout = int(raw_input("Output index of unspent output: "))
		k = getKey("Address of unspent output: ")
		inputs.append((txid, vout, k))
		amounts.append(int(decimal.Decimal(
			raw_input("Amount in unspent output (BCC): ")
			) * BCC))

	totalAmount = sum(amounts)
	print "Total of amounts: %s BCC" % str(decimal.Decimal(totalAmount)/BCC)

	fee = int(decimal.Decimal(
			raw_input("Transaction fee (BCC): ")
			) * BCC)

	destAddress = raw_input("Destination address: ")
	destHash = base58.decodeBase58Check(destAddress, 0) #PUBKEY_ADDRESS = 0

	destAmount = totalAmount - fee

	print "Amount sent to destination: %s BCC" % str(decimal.Decimal(destAmount)/BCC)
	if destAmount < 0:
		print "Negative amount is not allowed"
		sys.exit(2)
	'''
	if destAmount > totalAmount - fee:
		print "Not enough funds"
		sys.exit(1)
	'''

	tx = btx.Transaction(
		tx_in = [
			btx.TxIn(x[0], x[1])
			for x in inputs
			],
		tx_out = [
			btx.TxOut(destAmount, btx.Script.standardPubKey(destHash))
			]
		)

	'''
	changeKey = getKey("Address to send change amount to: ")
	changeAddress = getAddress(changeKey)
	changeHash = base58.decodeBase58Check(changeAddress, 0) #PUBKEY_ADDRESS = 0

	changeAmount = totalAmount - destAmount - fee
	if changeAmount < 0:
		raise Exception("Error: got negative change amount")
	elif changeAmount == 0:
		print "Note: change amount is zero - no change is sent"
	else:
		tx.tx_out.append(
			btx.TxOut(changeAmount, btx.Script.standardPubKey(changeHash))
			)
	'''

	for i in range(len(inputs)):
		#print tx.tx_in[i].previousOutputHash.encode("hex"), tx.tx_in[i].previousOutputIndex
		key = inputs[i][2]
		address = getAddress(key)
		hash = base58.decodeBase58Check(address, 0) #PUBKEY_ADDRESS = 0
		scriptPubKey = btx.Script.standardPubKey(hash)
		tx.signInput(i, scriptPubKey, [None, key.getPublicKey()], [key], amounts[i])

	print "Serialized transaction:"
	print tx.serialize().encode("hex")
	print "Transaction ID:", tx.getTransactionID()[::-1].encode("hex")


def decode(args):
	s = args[0]
	amounts = [int(decimal.Decimal(a)*BCC) for a in args[1:]]
	serialized = binascii.unhexlify(s)
	tx = btx.Transaction.deserialize(serialized)
	print 'lockTime: ', tx.lockTime
	for i in range(len(tx.tx_in)):
		tx_in = tx.tx_in[i]
		print 'TxIn:'
		print '    amount: ', amounts[i]
		print '    prevOutputHash: ', tx_in.previousOutputHash.encode("hex")
		print '    prevOutputIndex: ', tx_in.previousOutputIndex
		print '    sequenceNumber: %08x' % tx_in.sequenceNumber
		print '    script:'
		for e in tx_in.scriptSig.elements:
			if isinstance(e, str):
				s = e.encode("hex")
			else:
				s = str(e)
			print '        ', s
		signature, pubKey = tx_in.scriptSig.elements
		hashType = ord(signature[-1])
		signature = signature[:-1]

		k = Key()
		k.setPublicKey(pubKey)
		address = getAddress(k)
		hash = base58.decodeBase58Check(address, 0) #PUBKEY_ADDRESS = 0
		scriptPubKey = btx.Script.standardPubKey(hash)

		sigHash = tx.getSignatureBodyHash(i, scriptPubKey, hashType, amount=amounts[i])

		print '        pubKey: ', pubKey.encode('hex')
		print '        signature: ', signature.encode('hex')
		print '        hashType: %0x' % hashType
		print '        address: ', address
		print '        sigHash: ', sigHash.encode('hex')
		print '        valid: ', k.verify(sigHash, signature)
		print ''

	for tx_out in tx.tx_out:
		print 'TxOut:'
		print '    amount: ', tx_out.amount
		print '    script:'
		for e in tx_out.scriptPubKey.elements:
			if isinstance(e, str):
				s = e.encode("hex")
			else:
				s = '%0x' % e
			print '        ', s
		print ''



def test(args):
	k = Key()
	k.makeNewKey()
	data = "Hello world"
	sig = k.sign(data)
	print 'signature: ', sig.encode("hex")
	print k.verify(data, sig)



funcs = \
{
"getinfo": getinfo,
"decode": decode,
"spend": spend,
"test": test
}
funcNames = funcs.keys()
funcNames.sort()

if len(sys.argv) < 2 or sys.argv[1] not in funcNames:
	print "Usage: %s <command> [<args>]" % sys.argv[0]
	print "Command can be one of:"
	for fn in funcNames:
		print fn
	sys.exit(1)

funcs[sys.argv[1]](sys.argv[2:])

