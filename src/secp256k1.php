<?php
namespace CryptoPHP\Address;

class Secp256k1
{
    
    private $even = false;
    
    private function inverse($x, $p)
    {
        $inv1 = "1";
        $inv2 = "0";
        
        while ($p != "0" && $p != "1") {
            list($inv1, $inv2) = array(
                $inv2,
                gmp_sub($inv1, gmp_mul($inv2, gmp_div_q($x, $p)))
            );
            list($x, $p) = array(
                $p,
                gmp_mod($x, $p)
            );
        }
        return $inv2;
    }
    
    private function dblpt($point, $p)
    {
        if (is_null($point))
            return null;
        list($x, $y) = $point;
        if ($y == "0")
            return null;
        
        $slope = gmp_mul(gmp_mul(3, (gmp_mod(gmp_pow($x, 2), $p))), $this->inverse(gmp_mul(2, $y), $p));
        $xsum  = gmp_sub(gmp_mod(gmp_pow($slope, 2), $p), gmp_mul(2, $x));
        $ysum  = gmp_sub(gmp_mul($slope, (gmp_sub($x, $xsum))), $y);
        return array(
            gmp_mod($xsum, $p),
            gmp_mod($ysum, $p)
        );
    }
    
    private function addpt($p1, $p2, $p)
    {
        if ($p1 == null || $p2 == null)
            return null;
        
        list($x1, $y1) = $p1;
        list($x2, $y2) = $p2;
        if ($x1 == $x2)
            return $this->dblpt($p1, $p);
        
        $slope = gmp_mul(gmp_sub($y1, $y2), $this->inverse(gmp_sub($x1, $x2), $p));
        $xsum  = gmp_sub(gmp_mod(gmp_pow($slope, 2), $p), gmp_add($x1, $x2));
        $ysum  = gmp_sub(gmp_mul($slope, gmp_sub($x1, $xsum)), $y1);
        return array(
            gmp_mod($xsum, $p),
            gmp_mod($ysum, $p)
        );
    }
    
    private function ptmul($pt, $a, $p)
    {
        $scale = $pt;
        $acc   = null;
        
        while (substr($a, 0) != "0") {
            if (gmp_mod($a, 2) != "0") {
                if ($acc == null) {
                    $acc = $scale;
                } else {
                    $acc = $this->addpt($acc, $scale, $p);
                }
            }
            $scale = $this->dblpt($scale, $p);
            $a     = gmp_div($a, 2);
        }
        return $acc;
    }
    
    private function bchexdec($hex)
    {
        $dec = 0;
        $len = strlen($hex);
        for ($i = 1; $i <= $len; $i++) {
            $dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
        }
        $decArray = explode('.', $dec);
        $dec      = $decArray[0];
        return $dec;
    }
    
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
    
    private function pairToKey($array)
    {
        list($x, $y) = $array;
        $x = $this->bcdechex($x);
        $y = $this->bcdechex($y);
        if (substr($y, -1) % 2 == 0)
            $this->even = true;
        return ($this->compressed) ? $x : $x . $y;
    }
    
    public function private2public($privateKey)
    {
        $wif_prefixes = array(
            '9',
            'c',
            '5',
            'K',
            'L'
        );
        if (in_array(substr($privateKey, 0, 1), $wif_prefixes))
            $privateKey = $this->wif2key($privateKey);
        
        $p      = "115792089237316195423570985008687907853269984665640564039457584007908834671663";
        $Gx     = "55066263022277343669578718895168534326250603453777594175500187360389116729240";
        $Gy     = "32670510020758816978083085130507043184471273380659243275938904335757337482424";
        $g      = array(
            $Gx,
            $Gy
        );
        $n      = $this->bchexdec($privateKey);
        $pair   = $this->ptmul($g, $n, $p);
        $pubKey = $this->pairToKey($pair);
        if ($this->compressed) {
            if ($this->even) {
                return '02' . $pubKey;
            } else {
                return '03' . $pubKey;
            }
        } else
            return '04' . $pubKey;
    }
    
}
