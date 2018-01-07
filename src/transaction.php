<?php
namespace CryptoPHP;

class Transaction extends Address\Address
{
    private $balance = 0;
    public $network = "BTC";
    
    //build transaction
    public function build($input, $output, $privateKey, $amount, $fees)
    {
        
        //set inputs
        $in = $this->inputs($input, $amount + $fees);
        if ($in == null) {
            die(json_encode(array(
                "code" => 400,
                "error" => 'No unspent transactions'
            )));
        }
		        
        //if the balance is greater than the amount, pay ourselves
        if ($this->balance > $amount + $fees) {
            $scriptPubKey = $this->scriptPubKey($input);
            $out[]        = array(
                "value" => $this->balance - $amount - $fees,
                "scriptPubKey" => $scriptPubKey
            );
        }
        //if the balance is lower than the amount, throw error
        else if ($this->balance < $amount + $fees) {
            die(json_encode(array(
                "code" => 407,
                "error" => 'Balance is insufficient'
            )));
        }
        
        //build output
        $out[] = array(
            "value" => $amount,
            "scriptPubKey" => $this->scriptPubKey($output)
        );
        
        //build
        $locktime = 0;
        $version  = 1;
        $size     = count($in) * 180 + count($out) * 34 + 10;
        
        //sign inputs
        $in = $this->sign_inputs($in, $privateKey, $out, $locktime);
        
        //final raw
        $raw = $this->raw($in, $out, $locktime, true);
        
        return $raw;
    }
    
    //sign inputs
    private function sign_inputs($in, $privateKey, $out, $locktime)
    {
        $i = 0;
        foreach ($in as $input) {
            //remove scriptSig for other inputs
            $newIn = $in;
            for ($y = 0; $y > count($in); $y++) {
                if ($y != $i) {
                    $newIn[$y]["scriptSig"] = "";
                }
            }
            $raw                 = $this->raw($newIn, $out, $locktime, false);
            $hash                = $this->reverseHash(hash('sha256', hex2bin(hash('sha256', hex2bin($raw)))));
            $scriptSig           = $this->scriptSig($hash, $privateKey);
            $in[$i]["scriptSig"] = $scriptSig;
            $i++;
        }
        return $in;
    }
    
    //requirements
    private function requirements()
    {
        //php version
        $version = explode('.', PHP_VERSION);
        if ($version[0] . $version[1] < 71) {
            die(json_encode(array(
                "code" => 401,
                "error" => 'This library requires PHP verison > 7'
            )));
        }
        //check if we have secp256k1 available in SSL
        $curve_names = openssl_get_curve_names();
        if (!array_search('secp256k1', $curve_names)) {
            die(json_encode(array(
                "code" => 402,
                "error" => 'Looks like curve secp256k1 is not available. Please update the SSL version on your system.'
            )));
        }
        
    }
    
    //create scriptsig
    public function scriptSig($hash, $privateKey)
    {
        $wif_prefixes = array(
            '5',
            'c',
            'K',
            'L',
            '9'
        );
        if (in_array(substr($privateKey, 0, 1), $wif_prefixes)) {
            $privateKey = $this->wif2key($privateKey);
        }
        $publicKey = $this->private2public($privateKey);
        $signature = $this->sign($hash, $privateKey);
        $scriptSig[] = dechex(strlen($signature) / 2 + 1); //length of signature + 0x01
        $scriptSig[] = $signature; //der signature
        $scriptSig[] = '01';
        $scriptSig[] = dechex(strlen($publicKey) / 2); //length of public key
        $scriptSig[] = $publicKey;
        
        $scriptSig = implode("", $scriptSig);
        return $scriptSig;
    }
    
    //sign
    public function sign($hash, $privateKey)
    {
        //verify hash
        if (!ctype_alnum($hash)) {
            die(json_encode(array(
                "code" => 403,
                "error" => 'Invalid hash type when signing'
            )));
        }
        //create hex (key)
        $hex = '30740201010420' . $privateKey . 'a00706052b8104000aa144034200' . $this->private2public($privateKey);
        
        //format hex to PEM 
        $pemKey          = base64_encode(hex2bin($hex));
        $formattedPemKey = "
-----BEGIN EC PRIVATE KEY-----
" . chunk_split($pemKey, 64) . "-----END EC PRIVATE KEY-----";
        
        //try signing with PHP openssl
        $status = @openssl_sign($hash, $signature, $formattedPemKey, OPENSSL_ALGO_SHA256);
        if (!$status) {
            //try signing with CLI
            $temp   = tempnam(sys_get_temp_dir(), 'PEMKEY');
            $handle = fopen($temp, "w");
            fwrite($handle, $formattedPemKey);
            fclose($handle);
            $output = shell_exec('echo "' . $hash . '" | openssl dgst -sha256 -hex -sign ' . $temp);
            unlink($temp);
            $outputArray = explode(' ', $output);
            $signature   = @substr($outputArray[1], 0, -1);
            if (empty($signature) || !ctype_alnum($signature) || strlen($signature) < 50) {
                die(json_encode(array(
                    "code" => 404,
                    "error" => 'Could not sign transaction'
                )));
            }
        } else {
            $signature = bin2hex($signature);
        }
        return $signature;
    }
    
    //create raw transaction
    private function raw($in, $out, $locktime, $final)
    {
        //https://www.codeproject.com/Articles/1151054/Create-a-Bitcoin-transaction-by-hand
        //https://www.siliconian.com/blog/16-bitcoin-blockchain/22-deconstructing-bitcoin-transactions
        //https://bitcoin.stackexchange.com/questions/32628/redeeming-a-raw-transaction-step-by-step-example-required
        $raw[] = '01000000';
        $raw[] = $this->byteConverter(1, count($in));
        
        $i = 0;
        foreach ($in as $input) {
            $raw[] = $this->reverseHash($in[$i]["prev_out"]["hash"]);
            $raw[] = $this->byteConverter(4, $in[$i]["prev_out"]["n"]);
            $raw[] = ($final) ? dechex(strlen($in[$i]["scriptSig"]) / 2) : '19';
            $raw[] = $in[$i]["scriptSig"];
            $raw[] = 'ffffffff';
            $i++;
        }
        
        $raw[] = $this->byteConverter(1, count($out));
        
        $i = 0;
        foreach ($out as $output) {
            $raw[] = $this->byteConverter(8, bin2hex(pack("V", $out[$i]["value"] * 100000000)), false);
            $raw[] = '1976a914' . $this->stripPubKey($out[$i]["scriptPubKey"]) . '88ac';
            $i++;
        }
        
        $raw[] = $this->byteConverter(4, $locktime);
        if (!$final)
            $raw[] = '01000000';
        
        //echo implode("<br>",$raw).'<br><br>';
        $raw = implode("", $raw);
        
        return $raw;
    }
    
    private function stripPubKey($scriptPubKey)
    {
        $array = explode(' ', $scriptPubKey);
        return $array[2];
    }
    
    //convert number to needed byte 
    private function byteConverter($bytes, $n, $direction = true)
    {
        $zeros = '';
        for ($i = strlen($n); $i < $bytes * 2; $i++) {
            $zeros .= '0';
        }
        return ($direction) ? $zeros . $n : $n . $zeros;
    }
    
    //reverse hash for raw transaction
    private function reverseHash($hex)
    {
        $reversed = '';
        $hex      = strrev($hex);
        $hexArray = str_split($hex);
        $array    = array_chunk($hexArray, 2);
        foreach ($array as $chunk) {
            $reversed .= implode('', array_reverse($chunk));
        }
        
        return $reversed;
    }
    
    //get unspent inputs of input address
    private function inputs($address, $value)
    {
        //if inputs are already provided, get data
        if (is_array($address)) {
            $this->balance = $value;
            return $address;
        }
        
        //get unspent inputs from then network
        $Network = new \CryptoPHP\Network;
        $outputs = $Network->unspent($address, $this->network);
        
        $inputs = null;
        
        $n = 0;
        foreach ($outputs as $output) {
            $this->balance += $output['value'];
            
            $prev_out = array(
                "hash" => $output['hash'],
                "n" => $n
            );
            $inputs[] = array(
                "prev_out" => $prev_out,
                "scriptSig" => $output['scriptSig']
            );
            if ($this->balance >= $value)
                break;
            $n++;
        }
        return $inputs;
    }
    
    //broadcast transaction
    private function broadcast($hex)
    {
        
    }
    
    //get scriptPubKey from given address
    public function scriptPubKey($address)
    {
        $binary       = $this->base58Decode($address);
        $scriptPubKey = ($this->segwit) ? substr($binary, 3, -8) : substr($binary, 2, -8);
        return 'OP_DUP OP_HASH160 ' . $scriptPubKey . ' OP_EQUALVERIFY OP_CHECKSIG';
    }
}