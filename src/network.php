<?php
namespace CryptoPHP;

class Network
{
    
    //list unspent transactions
    public function unspent($address, $network)
    {
        $txs = array();
        
        $url     = 'https://chain.so/api/v2/get_tx_unspent/' . $network . '/' . $address;
        $content = $this->request($url);
        $json    = json_decode($content);
        
        foreach ($json->data->txs as $tx) {
            $txs[] = array(
                "hash" => $tx->txid,
                "scriptSig" => $tx->script_hex,
                "value" => $tx->value
            );
        }
        
        return $txs;
    }
	
	//get transaction outputs
	public function transaction_outputs($inputs, $network, $address)
	{
        $txs = array();
        
		foreach ($inputs as $txid)
		{
			$url     = 'https://chain.so/api/v2/get_tx_outputs/' . $network . '/' . $txid;
			$content = $this->request($url);
			$json    = json_decode($content);
			
			foreach ($json->data->outputs as $tx) {
				if ($tx -> address == $address)
				{
					$txs[] = array(
						"hash" => $txid,
						"scriptSig" => explode(' ',$tx->script)[2],
						"value" => $tx->value
					);
				}
			}
		}

        return $txs;
	}
    
    //handler for fetching content
    private function request($url)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            'user-agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/' . rand(1, 1000) . '.36'
        ));
        $server_output = curl_exec($ch);
        curl_close($ch);
        return $server_output;
    }
    
}