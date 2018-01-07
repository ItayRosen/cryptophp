<?php
require('../src/CryptoPHP.php');

/*
Optional variables: currency (btc by default), segwit (false by default), testnet (false by default), compressed (false by default)
Syntax: generate(input); input can be either null for random private key, an existing private key (to generate wif / public address from it) or a brainwallet string
*/

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