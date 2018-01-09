<?php
require('../src/CryptoPHP.php');

/*
Optional variables: currency (btc by default), segwit (false by default), testnet (false by default), compressed (false by default), bip39 (false by default), salt (for bip39 seed hashing. defaults to empty)
Syntax: generate(input); input can be either null for random private key, an existing private key (to generate wif / public address from it) or a brainwallet string
*/

/*

//generate a bitcoin address
$address = new CryptoPHP\transaction;
echo $address -> generate();

//generate a bitcoin testnet address
$address = new CryptoPHP\transaction;
$address -> testnet = true;
echo $address -> generate();

//generate a bitcoin compressed address
$address = new CryptoPHP\transaction;
$address -> compressed = true;
echo $address -> generate();

//generate a bitcoin segwit address
$address = new CryptoPHP\transaction;
$address -> segwit = true;
echo $address -> generate();

//generate a litecoin address
$address = new CryptoPHP\transaction;
$address -> currency = 'ltc';
echo $address -> generate();

//generate a vanity address
$address = new CryptoPHP\transaction;
echo $address -> vanity('hi');

*/

//generate a bip39 seed
$address = new CryptoPHP\transaction;
$address -> bip39 = true;
echo $address -> generate('throw repair seek ripple various favorite awkward cluster cheap deal fabric craft legend head column');