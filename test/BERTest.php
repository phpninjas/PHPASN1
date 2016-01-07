<?php

namespace phpninjas\ASN1\Test;

use PHPUnit_Framework_TestCase;
use phpninjas\ASN1\BER;

class BERTest extends PHPUnit_Framework_TestCase
{

    public function testEncodedCompoundWith2Ints()
    {
        // double integer (der encoded ecdsa pubkey)
        $origHex = "3046022100e26d9ff76a07d68369e5782be3f8532d25ecc8add58ee256da6c550b52e8006b022100b4431f5a9a4dcb51cbdcaae935218c0ae4cfc8aa903fe4e5bac4c208290b7d5d";

        $shouldBeInt = new BER($origHex, true);

        $this->assertThat(bin2hex($shouldBeInt->getEncoded()), $this->equalTo($origHex));

    }

    public function testBitString(){

        $binaryData = chr(BER::BIT_STRING);
        $binaryData .= chr(0x03);
        $binaryData .= chr(0x05);
        $binaryData .= chr(0xFF);
        $binaryData .= chr(0xA0);
        $expectedEncoding = hex2bin("030305FFA0");

        $ber = new BER($binaryData);

        $this->assertEquals($ber->getContent(), [0x05,0xFF,0xA0]);
        $this->assertEquals($ber->getEncoded(), $expectedEncoding);

    }

    public function testLengthLongerThanData(){
        $someencodedstring = hex2bin("020210"); # 2 byte length only 1 byte data.
        $ber = new BER($someencodedstring);
        $ber->isContentType(BER::INTEGER); # => true
        $this->assertThat($ber->asInteger(), $this->equalTo(4096));
    }

    public function testHelloWorld(){

        $binary = chr(BER::CHARACTER_STRING);
        $binary .= hex2bin("0B68656c6c6f20776f726c64");

        $ber = new BER($binary);

        $this->assertTrue($ber->isContentType(BER::CHARACTER_STRING));
        $this->assertThat($ber->asString(), $this->equalTo("hello world"));
    }


}

