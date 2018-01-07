<?php
namespace CryptoPHP\Address;

class Address extends Secp256k1
{
    
    public $testnet = false;
    public $segwit = false;
    public $currency = 'btc';
    public $compressed = false;
    
    public function base58Decode($hex)
    {
        //create val to char array
        $string  = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $int_val = "0";
        for ($i = strlen($hex) - 1, $j = "1", $base = strlen($string); $i >= 0; $i--, $j = gmp_mul($j, $base)) {
            $q       = @gmp_mul($j, strval(strpos($string, $hex{$i})));
            $int_val = gmp_add($int_val, $q);
        }
        $hex = $this->bcdechex($int_val);
        if (strlen($hex) == 47)
            $hex = '0' . $hex; //sometimes the first characters (0?) gets cut off. Why?
        if (!$this->testnet)
            $hex = '00' . $hex;
        return $hex;
    }
    
	//decimal to hex
    private function bcdechex($dec)
    {
        $hex = '';
        do {
            $last = bcmod($dec, 16);
            $hex  = dechex($last) . $hex;
            $dec  = bcdiv(bcsub($dec, $last), 16);
        } while ($dec > 0);
        return $hex;
    }
    
    public function base58Encode($hex)
    {
        $address = '';
        //create val to char array
        $string  = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        for ($i = 0; $i <= 57; $i++) {
            $array[$i] = $string[0];
            $string    = substr($string, 1);
        }
        //hex to dec
        $dec = 0;
        $len = strlen($hex);
        for ($i = 1; $i <= $len; $i++) {
            $dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
        }
        //round dec
        $nArray = explode(".", $dec);
        $n      = $nArray[0];
        //loop through characters
        while ($n >= 1) {
            //get the reminder from 58
            $reminder = gmp_strval(gmp_mod($n, "58"));
            //convert it to char and add to address
            $address  = $array[$reminder] . $address;
            //start over 
            $n        = gmp_div_q($n, 58);
        }
        //add the last bit
        return $address;
    }
    
	//public key to public address
    public function key2address($publicKey)
    {
        if ($publicKey == "" || strlen($publicKey) < 66 || strlen($publicKey) > 140)
            die(json_encode(array(
                "code" => 409,
                "error" => 'Error with public key. Try again perhaps?'
            )));
        
        $sha      = @hash('sha256', hex2bin($publicKey));
        $ripe     = hash('ripemd160', hex2bin($sha)); //keyhash / pubkeyhash 
        $netByte  = $this->prefixes('netByte');
        $version  = $netByte . $ripe; //redeemScript / segwitP2PKH / pkscript / script_sig
        $sha      = hash('sha256', hex2bin($version));
        $ripe     = hash('ripemd160', hex2bin($sha)); //p2sh_script_hash160 / address_bytes
        $sha      = hash('sha256', hex2bin($sha));
        $checksum = ($this->segwit) ? substr(hash('sha256', hex2bin(hash('sha256', hex2bin('05' . $ripe)))), 0, 8) : substr($sha, 0, 8);
        $binary   = ($this->segwit) ? '05' . $ripe . $checksum : $version . $checksum;
        $address  = $this->base58Encode($binary); //multisig address
        if ($this->currency == 'btc' && !$this->segwit && !$this->testnet) {
            $address = '1' . $address;
        }
        return $address;
    }
    
	//prefixes for different currencies / networks
    private function prefixes($type)
    {
        //https://en.bitcoin.it/wiki/List_of_address_prefixes
        $currency = $this->currency;
        
        if ($this->testnet) {
            $currency = $currency . '_T';
        } elseif ($this->segwit && $type != 'wifPrefix') {
            $currency = $currency . '_S';
        }
        
        $prefixes['netByte']   = array(
            'btc' => '00',
            'btc_S' => '0014',
            'btc_T' => '6F',
            'ltc' => '30',
            'ltc_T' => '6F',
            'doge' => '1E',
            'nmc' => '34'
        );
        $prefixes['wifPrefix'] = array(
            'btc' => '80',
            'btc_T' => 'EF',
            'ltc' => 'B0',
            'doge' => '9E',
            'nmc' => 'B4'
        );
        
        if (!isset($prefixes[$type][$currency])) {
            die(json_encode(array(
                "code" => 405,
                "error" => 'Unknown prefix. Type: ' . $type . '. Currency: ' . $currency
            )));
        }
        
        return $prefixes[$type][$currency];
    }
    
	//private key (hex) to wif format
    public function key2wif($privateKey)
    {
        $byte     = $this->prefixes('wifPrefix') . $privateKey;
        $sha      = (hash('sha256', hex2bin($byte)));
        $sha2     = (hash('sha256', hex2bin($sha)));
        $checksum = substr($sha2, 0, 8);
        $addition = ($this->compressed) ? $byte . '01' . $checksum : $byte . $checksum;
        $wif      = $this->base58Encode($addition);
        return $wif;
    }
    
	//wif format to private key (hex)
    public function wif2key($wif)
    {
        $wif_prefixes = array(
            '9',
            'c',
            'K',
            'L',
            '5'
        );
        if (!in_array(substr($wif, 0, 1), $wif_prefixes))
            die(json_encode(array(
                "code" => 406,
                "error" => 'Invalid WIF prefix'
            )));
        
        $end        = (substr($wif, 0, 1) == 'c') ? -10 : -8;
        $privateKey = substr($this->base58Decode($wif), 2, $end);
        return $privateKey;
    }
    
	//create a private key (from a given input or random bytes)
    private function privateKey($input = null)
    {
        if ($input == null) {
            if (function_exists('random_bytes')) {
                $privateKey = bin2hex(random_bytes(32));
            } else {
                $privateKey = bin2hex(openssl_random_pseudo_bytes(32));
            }
        } elseif (strlen($input) == 64) {
			$privateKey = $input;
        }
		else {
			$privateKey = hash('sha256', ($input));
		}
        
        return $privateKey;
    }
    
	//generate a new address
    public function generate($input = null)
    {
        if ($this->segwit)
            $this->compressed = true;
        $privateKey    = $this->privateKey($input);
        $wif           = $this->key2wif($privateKey);
        $publicKey     = $this->private2public($privateKey);
        $publicAddress = $this->key2address($publicKey);
        
        $json = json_encode(array(
            "privateKey" => $privateKey,
            "wif" => $wif,
            "publicAddress" => $publicAddress
        ));
        return $json;
    }
    
}