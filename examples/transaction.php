<?php
require('../src/CryptoPHP.php');

/*
Syntax: build(input address/tx ids,output address, private key (wif/hex), btc to spend, fees);
Optional variabales: network (BTC, BTCTEST, LTC, LTCTEST, DOGE, DOGETEST, DASH, DASHTEST)
*/

//generate a transaction from address A to B
$transaction = new CryptoPHP\Transaction;
echo $transaction -> build('1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E','13ZAJdTYfxsKi3yGHm568t1Eg4gvBSwu8t','5JN72fM3NWLV4dM1F4LiJ9evbtznwJu3iwxKfQsocL86X4JiRLe',1,0.0001);

//generate a testnet transaction from address A to B
$transaction = new CryptoPHP\Transaction;
$transaction -> network = "BTCTEST";
echo $transaction -> build('mxxBodAFQfYjYKU57qDDpCSfrpAoFR4Dyz','mnA9EnjuZCJjqsU6mGMZUQk7jXVv36bgk3','92uvngavxoBWr7ZLfPXtjbXHYKLQCpbCsvdghUC3xuwNgvHiwZ5',1,0.0001);

//spend predefined inputs
$transaction = new CryptoPHP\Transaction;
$inputs[] = array("prev_out" => array("hash" => "a05f60a9679a1ad0ef57b092006b6c01886291a2ff696f5e2ac107b349594cf6", "n" => 0), "scriptSig" => "166749c16df955750990623397be66e965863611");
echo $transaction -> build($inputs,'13ZAJdTYfxsKi3yGHm568t1Eg4gvBSwu8t','5JN72fM3NWLV4dM1F4LiJ9evbtznwJu3iwxKfQsocL86X4JiRLe',1,0.0001);