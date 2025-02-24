#    cashaddr.py
#    Copyright (C) 2025 by CJP
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

#https://bch.info/en/specifications



prefix = b'bitcoincash'
checksumPrefix = [c & 31 for c in prefix] + [0]

checksumLength = 8 #40 bits / 5 bits

base32chars = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'



def polyMod(data):
	'''
	Calculates the PolyMod checsum over the given data
	
	Arguments:
	data: list of int; the data to calculate the checksum over
	
	Return value:
	int; the checksum
	'''

	c = 1
	for d in data:
		c0 = (c >> 35) & 0xff
		c = ((c & 0x07ffffffff) << 5) ^ d
		if c0 & 0x01: c ^= 0x98f2bc8e61
		if c0 & 0x02: c ^= 0x79b76d99e2
		if c0 & 0x04: c ^= 0xf33e5fb3c4
		if c0 & 0x08: c ^= 0xae2eabe2a8
		if c0 & 0x10: c ^= 0x1e4f43e470

	return c ^ 1


def base32ToBytes(data):
	'''
	Converts from base32 integers to bytes
	
	Arguments:
	data: list of int
	
	Return value:
	bytes
	'''

	value = 0
	for d in data:
		value = (value << 5) | d
	
	bits = len(data)*5
	relevantBytes = bits // 8
	paddingBits = bits % 8

	padding = value & ((1 << paddingBits) - 1)
	if padding != 0:
		raise Exception('Padding bits are not zero')
	value >>= paddingBits

	return value.to_bytes(relevantBytes, 'big')


def decode(address):
	'''
	Decodes a Bitcoin Cash address

	Arguments:
	address: str; the to-be-decoded address
	
	Return value:
	tuple (version, hash)
	version: int; the version number. Example values:
		P2KH: 0
		P2SH: 8
	hash: bytes; the payload
	'''

	values = [base32chars.index(c) for c in address.lower()]

	checksum = polyMod(checksumPrefix + values)
	if checksum != 0:
		raise Exception('Checksum failure')

	versionAndHash = values[:-checksumLength]
	versionAndHash = base32ToBytes(versionAndHash)

	return versionAndHash[0], versionAndHash[1:]



import sys
print(decode(sys.argv[-1]))

