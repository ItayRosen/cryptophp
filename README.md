# CryptoPHP
This is a library for cryptocurrencies in pure PHP.
# The library is not production ready.
# Supported
*Currencies: Bitcoin, Litecoin, Bitcoin Cash, DogeCoin, Namecoin
*Networks: Mainnet, Testnet
*Features: Segwit (not complete), compressed keys,
*Operations: Address generation, Format conversion (wif, hex, private -> public, pem), build transaction
# Needs attention
*DER signature is incorrect and not accepted as a valid scriptSig.
*Although segwit address generation works, it has still not been implemented in a transaction
# Future development
*Lightning network support
*Support more currencies