<?php
error_reporting(-1);
// $s = new Salsa20(hex2bin("a8fe0b92710fde99bd12672152b2ac91fd1c0843df9a5c9baa08589fc37e55ba"),hex2bin("ca50c323e91aa237"));
// $e = $s->encrypt(bin2hex('php is great'));
// var_dump(bin2hex($e));
// $xxx = str_repeat('a',256);
// $ss = $s->encrypt($xxx);
// var_dump(bin2hex($ss));


class Salsa20
{
#public static $TAU    = [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574];
public static $SIGMA  = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

public $salsa_key;
public $salsa_iv;
public $salsa_rounds;

public $key_state;
public $state;
public $lastchunk;

public function __construct($k,$iv,$rounds = 20)
	{
	$this->salsa_key = $this->setup_key($k);#self._key_setup(key)
	$this->salsa_iv = $this->setup_iv($iv);#self.iv_setup(iv)
	$this->salsa_rounds = $rounds; #self.ROUNDS = rounds
	}

private function setup_key($salsa_key)
	{
	if (strlen($salsa_key) != 32) #hex...
		throw new \LengthException('Key must be 32 bytes');
		
	$key_state = array_fill(0,16,0);
	$k = array_values(unpack('L8',$salsa_key));#k = list(struct.unpack('<8I', key))
		
	$key_state[0]  = self::$SIGMA[0];
    $key_state[1]  = $k[0];
    $key_state[2]  = $k[1];
    $key_state[3]  = $k[2];
    $key_state[4]  = $k[3];
    $key_state[5]  = self::$SIGMA[1];

    $key_state[10] = self::$SIGMA[2];
    $key_state[11] = $k[4];
    $key_state[12] = $k[5];
    $key_state[13] = $k[6];
    $key_state[14] = $k[7];
    $key_state[15] = self::$SIGMA[3];	
	
	$this->key_state = $key_state;
	}

private function setup_iv($salsa_iv)
	{
	if (strlen($salsa_iv) != 8)
        throw new \LengthException('iv must be 8 bytes');
    $iv_state = $this->key_state;
    $v = array_values(unpack('L2',$salsa_iv));
    $iv_state[6] = $v[0];
    $iv_state[7] = $v[1];
    $iv_state[8] = 0;
    $iv_state[9] = 0;
    $this->state = $iv_state;
    $this->lastchunk = 64;  	
	}	
	
public function ROL32($a,$b)
	{
	 return (($a << $b) | ($a >> (32 - $b))) & 0xffffffff;	
	}	

	
public function xXor($stream, $din)
	{
	$dout = "";
		for($i=0;$i<strlen($din);$i++) #for i in range(len(din)):
		{ $dout[$i] = $stream[$i] ^ $din[$i]; } #dout.append(stream[i]^din[i])
		return $dout;	
	}	
	
private function salsa20_scramble()#output must be converted to bytestring before return.
{
$x = $this->state;  # makes a copy
        
	for ($i=$this->salsa_rounds; $i > 0; $i-=2) #for i in range(self.ROUNDS, 0, -2):
		{
		$x[4] ^= $this->ROL32( ($x[ 0]+$x[12]) & 0xffffffff,  7);
		$x[ 8] ^= $this->ROL32( ($x[ 4]+$x[ 0]) & 0xffffffff,  9);
		$x[12] ^= $this->ROL32( ($x[ 8]+$x[ 4]) & 0xffffffff, 13);
		$x[ 0] ^= $this->ROL32( ($x[12]+$x[ 8]) & 0xffffffff, 18);
		$x[ 9] ^= $this->ROL32( ($x[ 5]+$x[ 1]) & 0xffffffff,  7);
		$x[13] ^= $this->ROL32( ($x[ 9]+$x[ 5]) & 0xffffffff,  9);
		$x[ 1] ^= $this->ROL32( ($x[13]+$x[ 9]) & 0xffffffff, 13);
		$x[ 5] ^= $this->ROL32( ($x[ 1]+$x[13]) & 0xffffffff, 18);
		$x[14] ^= $this->ROL32( ($x[10]+$x[ 6]) & 0xffffffff,  7);
		$x[ 2] ^= $this->ROL32( ($x[14]+$x[10]) & 0xffffffff,  9);
		$x[ 6] ^= $this->ROL32( ($x[ 2]+$x[14]) & 0xffffffff, 13);
		$x[10] ^= $this->ROL32( ($x[ 6]+$x[ 2]) & 0xffffffff, 18);
		$x[ 3] ^= $this->ROL32( ($x[15]+$x[11]) & 0xffffffff,  7);
		$x[ 7] ^= $this->ROL32( ($x[ 3]+$x[15]) & 0xffffffff,  9);
		$x[11] ^= $this->ROL32( ($x[ 7]+$x[ 3]) & 0xffffffff, 13);
		$x[15] ^= $this->ROL32( ($x[11]+$x[ 7]) & 0xffffffff, 18);

		$x[ 1] ^= $this->ROL32( ($x[ 0]+$x[ 3]) & 0xffffffff,  7);
		$x[ 2] ^= $this->ROL32( ($x[ 1]+$x[ 0]) & 0xffffffff,  9);
		$x[ 3] ^= $this->ROL32( ($x[ 2]+$x[ 1]) & 0xffffffff, 13);
		$x[ 0] ^= $this->ROL32( ($x[ 3]+$x[ 2]) & 0xffffffff, 18);
		$x[ 6] ^= $this->ROL32( ($x[ 5]+$x[ 4]) & 0xffffffff,  7);
		$x[ 7] ^= $this->ROL32( ($x[ 6]+$x[ 5]) & 0xffffffff,  9);
		$x[ 4] ^= $this->ROL32( ($x[ 7]+$x[ 6]) & 0xffffffff, 13);
		$x[ 5] ^= $this->ROL32( ($x[ 4]+$x[ 7]) & 0xffffffff, 18);
		$x[11] ^= $this->ROL32( ($x[10]+$x[ 9]) & 0xffffffff,  7);
		$x[ 8] ^= $this->ROL32( ($x[11]+$x[10]) & 0xffffffff,  9);
		$x[ 9] ^= $this->ROL32( ($x[ 8]+$x[11]) & 0xffffffff, 13);
		$x[10] ^= $this->ROL32( ($x[ 9]+$x[ 8]) & 0xffffffff, 18);
		$x[12] ^= $this->ROL32( ($x[15]+$x[14]) & 0xffffffff,  7);
		$x[13] ^= $this->ROL32( ($x[12]+$x[15]) & 0xffffffff,  9);
		$x[14] ^= $this->ROL32( ($x[13]+$x[12]) & 0xffffffff, 13);
		$x[15] ^= $this->ROL32( ($x[14]+$x[13]) & 0xffffffff, 18);	
		}
            
    for ($i=0;$i<16;$i++) #for i in range(16):
		{
		$x[$i] = ($x[$i] + $this->state[$i]) & 0xffffffff;	#x[i] = (x[i] + self.state[i]) & 0xffffffff
		}					
        $output = pack('L16',$x[0],$x[1],$x[ 2], $x[ 3],$x[ 4], $x[ 5], $x[ 6], $x[ 7],$x[ 8], $x[ 9], $x[10], $x[11], $x[12], $x[13], $x[14], $x[15]);				
							
    return $output;            	
}

public function encrypt($datain) #datain and dataout are bytestrings.
{
	#if ($this->lastchunk != 64) #эта херня и в оригинале закоментирована была
		#die('size of last chunk not a multiple of 64 bytes');
	$dataout = '';
	$stream  = '';
	$start = 0;
	$datalen = strlen($datain);
    while (true)#тут надо подумать!    while datain:
	{
		$stream = $this->salsa20_scramble();
        $this->state[8] += 1;
            if ($this->state[8] == 0)        # if overflow in state[8]
				{$this->state[9] += 1;}      # carry to state[9]
                # not to exceed 2^70 x 2^64 = 2^134 data size ??? <<<<
				
			$chunk = substr($datain,$start,64);
			$start += 64;
					
            $dataout .= $this->xXor($stream, $chunk);
            if ((strlen($chunk) < 64 ) || ($start >= $datalen)) #в оригинале - меньше равно 64, так что такой "фикс". Вдруг строка кратна 64..
			{
			#$this->lastchunk = strlen($chunk); #надо ли оно?
                return $dataout;
			}
	}
	throw new \LogicException('Fatal err?');
}

	
}
