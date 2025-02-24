Bitcoin Cash Off The Grid (BCHOTG)
==================================

Low-level tool for creating Bitcoin Cash transactions.

This tool solves the problem of how to move your Bitcoin Cash funds if you
don't trust any of the Bitcoin Cash clients. This tool does not establish any
network connections, it does not modify anything on your hard disk, and since it
is a relatively small amount of code, written in Python, it is relatively easy
to audit the code. Because of this, it should be easier to establish trust in
this tool than in full-featured Bitcoin Cash clients.

Please read the file "LICENSE" for licensing information.


System requirements
===================

A (preferrably Linux or other UNIX-like) system with Python 3.x and the Python
secp256k1 library (e.g. `pip install secp256k1`).

How to use
==========

WARNING: this is a low-level tool, and correct usage requires great care and
some insight in how cryptocurrencies work. Mistakes are easily made, and this
software does not protect against your own mistakes. Mistakes can lead to
unrecoverable loss of funds. The author of this software will not compensate
ANY loss of funds caused by the use of this software, either caused by incorrect
usage or by bugs in the software itself. USE AT YOUR OWN RISK!

Step 1: obtain your private keys
--------------------------------
This step assumes you have a wallet that contains private keys that give access
to some Bitcoin Cash funds. This can, for instance, be

 * a Bitcoin wallet that contained funds before the Bitcoin Cash fork
 * a Bitcoin Cash wallet
 * a Bitcoin wallet with an address to which, accidentally, Bitcoin Cash was
   transferred

In the first case you could, as a precaution, first ensure the safety of the
Bitcoin funds on your addresses by moving the Bitcoin funds somewhere else,
before using BCHOTG. This is only a precaution, since I believe this is not
necessary, because BCHOTG only makes Bitcoin Cash transactions, which are
invalid on the Bitcoin network.

In ANY case, it is a good precaution to make a good back-up of your wallets
BEFORE you perform potentially risky operations.

Now, you need to identify the addresses that contain unspent Bitcoin Cash.
You can check this on a Bitcoin Cash block explorer, for instance on
https://blockchair.com/bitcoin-cash
Unfortunately, BCHOTG only supports regular Bitcoin addresses: there is no
support for P2SH, multi-sig or alternative script types.

Next, you need to obtain the private keys of any of these unspent outputs you
wish to spend. This works different in different wallet software. In Bitcoin
Core, for instance, you can go to "Debug window"->"Console", and use the command

	dumpprivkey <address>

BCHOTG requires the Wallet Import Format; typically, private keys in this format
start with a 5, an L or a K.

You should store each private key in a separate file. The file should be a text
file with a single line, only containing the private key. As a convenience, you
could use the corresponding Bitcoin address as filename.

Step 2: check the private keys
------------------------------
In a commandline window, go to the directory that contains BCHOTG, and give
the command

	./bchotg.py getinfo <file1> [<file2> [..]]

where the files containing the private keys are given as commandline arguments.
It should return information like:

	----------------
	Filename:  <file>
	Public key:  <hex string>
	Address:  <Bitcoin address> (BTC); <Bitcoin Cash address> (BCH)

Verify that the Bitcoin addresses in the output are as expected.

Step 3: collect transaction output information
----------------------------------------------
You should find out where your funds are in the (Bitcoin Cash) blockchain.
This can be done with an online block explorer, for instance on

https://blockchair.com/bitcoin-cash

For each unspent transaction output, collect the following information:

 * The transaction ID of the transaction that sent funds to your address
 * The output index, of that transaction, that sent funds to your address.
   The first output has index 0, the second output has index 1, and so on.
 * The exact(!) amount of BCH that was sent to that output by the transaction.

Note: they should be UNSPENT outputs! Trying to spend an output that is already
spent by another transaction results in a double-spend; if you do that, your
transaction will be ignored by Bitcoin Cash.

Step 4: construct your transaction
----------------------------------
In a commandline window, go to the directory that contains BCHOTG, and give
the command

	./bchotg.py spend <file1> [<file2> [..]]

where the files containing the private keys are given as commandline arguments.

BCHOTG will ask for further information. First, the unspent transaction outputs:

	Transaction ID of unspent output (Enter to stop): <txid>
	Output index of unspent output: <index>
	1 <address1>
	2 <address2>
	...
	Address of unspent output: <choose a number from the above items>
	Amount in unspent output (BCH): <amount in the UTXO>

Continue with this for all UTXOs you wish to spend, and then press Enter to stop.
BCHOTG will then show the sum of all UTXO amounts you entered. Check this:

	Total of amounts: <amount> BCH

Next, BCHOTG asks for the transaction fee:

	Transaction fee (BCH): <fee>

BE CAREFUL: BCHOTG does NOT CHECK the sanity of this value! Any funds used as
transaction fee will be LOST (to you). You can easily lose a large part of your
funds by choosing a too high transaction fee.

Next, BCHOTG asks for the destination address:

	Destination address: <address>

Next, BCHOTG reports the amount sent to the destination address, by subtracting
the fee from the total of the input amounts:

	Amount sent to destination: <amount> BCH

Check this value.

Note: BCHOTG does NOT send any funds to a change address: all input funds are
used either for transaction fee, or sent to the destination address.

Finally, BCHOTG returns the raw transaction data, and the transaction ID:

	Serialized transaction:
	<raw transaction data>
	Transaction ID: <txid>

Save this information somewhere: you will use it in the next steps.

Now is a good time to double-check the destination address and the transaction
fee you entered earlier.

Step 5: check the transaction
-----------------------------

In a commandline window, go to the directory that contains BCHOTG, and give
the command

	./bchotg.py decode <raw transaction data> <amount1> [<amount2> [..]]

Use the raw transaction data from step 4. The amounts should be the amounts of
the unspent transaction outputs, in the order they were specified in step 4.

Check the information returned by BCHOTG, especially the amounts and addresses.

Step 6: broadcast the transaction
---------------------------------

Find a place to broadcast Bitcoin Cash transactions. This can be done, for
instance, on
https://blockchair.com/broadcast

Enter the raw transaction data from step 4. Check that the transaction is
accepted. Check the confirmation status of the transaction using a Bitcoin
Cash block explorer and the transaction ID from step 4.

