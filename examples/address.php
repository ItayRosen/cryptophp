<?php
require('../src/CryptoPHP.php');
use CryptoPHP\address;
use CryptoPHP\address\sepc256k1;

echo Address::generate();