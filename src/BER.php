<?php

namespace phpninjas\ASN1;

/**
 * @link https://en.wikipedia.org/wiki/X.690#BER_encoding
 * This class is largely based from the wikipedia entry for BER encoding.
 *
 * @note Long Form is NOT supported here mainly because working with byte streams
 * is slightly harder for PHP to do without writing additional classes to handle
 * streams.
 * For the sake of simplicity this has not been implemented.
 *
 * Class BER
 * @package ASN1
 */
class BER
{

    /**
     * Primitive/Constructed list of bytecodes.
     */
    const EOC               = 0x00;
    const BOOLEAN           = 0x01;
    const INTEGER           = 0x02;
    const BIT_STRING        = 0x03;
    const OCTET_STRING      = 0x04;
    const NULL              = 0x05;
    const OBJECT_IDENTIFIER = 0x06;
    const OBJECT_DESCRIPTOR = 0x07;
    const EXTERNAL          = 0x08;
    const REAL              = 0x09;
    const ENUMERATED        = 0x0A;
    const EMBEDDED_PDV      = 0x0B;
    const UTF8_STRING       = 0x0C;
    const RELATIVE_OID      = 0x0D;
    // value 0x0E and 0x0F are reserved for future use

    const SEQUENCE          = 0x10;
    const SET               = 0x11;
    const NUMERIC_STRING    = 0x12;
    const PRINTABLE_STRING  = 0x13;
    const T61_STRING        = 0x14;
    const VIDEOTEX_STRING   = 0x15;
    const IA5_STRING        = 0x16;
    const UTC_TIME          = 0x17;
    const GENERALIZED_TIME  = 0x18;
    const GRAPHIC_STRING    = 0x19;
    const VISIBLE_STRING    = 0x1A;
    const GENERAL_STRING    = 0x1B;
    const UNIVERSAL_STRING  = 0x1C;
    const CHARACTER_STRING  = 0x1D;
    const BMP_STRING        = 0x1E;
    const LONG_FORM         = 0x1F;

    /**
     * Masks for various identifier bit work.
     * @var int
     */
    private $classMask = 0xC0;
    private $pcMask = 0x20;
    private $tagMask = 0x1F;
    private $longFormMask = 0x80;
    private $longFormLengthMask = 0x7F;

    /**
     * Classes of identifier.
     * (bitshifted)
     */
    const CLASS_UNIVERSAL = 0;
    const CLASS_APPLICATION = 1;
    const CLASS_CONTEXT_SPECIFIC = 2;
    const CLASS_PRIVATE = 3;

    /**
     * Private class properties
     */
    private $class;
    private $isCompound;
    private $contentType;
    private $contentLength = 0;
    private $content;

    private $numLengthBytes = 1;

    /**
     * Construct a TLV (type-length-value) object from some input, either
     * hex or array of bytes (ints in the case of PHP because INTS EVERYWHERE!)
     *
     * @param $bytes array of bytes or hex string
     * @param bool $isHex
     */
    public function __construct($bytes, $isHex = false)
    {
        if (is_string($bytes)) {
            $bytes = array_values(unpack("C*", $isHex?hex2bin($bytes):$bytes));
        }
        $firstByte = array_shift($bytes);
        $this->class = ($firstByte & $this->classMask) >> 6;
        $this->isCompound = (boolean)(($firstByte & $this->pcMask) >> 5);
        $this->contentType = $firstByte & $this->tagMask;
        $this->parseLength($bytes);
        $this->parseContent($bytes);
    }

    /**
     * Chomp the length bytes off the array to find out how long the content is.
     *
     * @param $bytes
     * @return int|mixed
     */
    private function parseLength(&$bytes)
    {
        $contentLength = $byte = array_shift($bytes);
        if (($byte & $this->longFormMask) === $this->longFormMask) {
            $contentLength = 0;
            $extraLengthBytes = intval($byte & $this->longFormLengthMask);
            $this->numLengthBytes += $extraLengthBytes;
            while ($extraLengthBytes-- > 0) {
                $contentLength = ($contentLength << 8) | (array_shift($bytes) & 0xFF);
            }
        }
        return $this->contentLength = $contentLength;
    }

    /**
     * Retrieve an encoded variant of this TLV
     * as a character string.
     * @return string
     */
    public function getEncoded()
    {

        $bytes = [];
        $length = $this->getContentLength();
        if ($this->getNumLengthBytes() > 1) {
            for ($i = 0; $i < $this->numLengthBytes; $i++) {
                array_unshift($bytes, ($length >> (8 * $i)) & 0xFF);
            }
            array_unshift($bytes, $this->longFormMask | $length);
        } else {
            array_unshift($bytes, $this->longFormLengthMask & $length);
        }
        $identifier = ($this->class << 6) | ($this->isCompound << 5) | $this->contentType;
        array_unshift($bytes, $identifier);
        if ($this->isCompound) {
            $encoded = "";
            foreach ($this->content as $content) {
                $encoded .= $content->getEncoded();
            }
            return call_user_func_array('pack', array_merge(["C*"], $bytes)) . $encoded;
        } else {
            $bytes = array_merge($bytes, $this->getContent());
            return call_user_func_array('pack', array_merge(["C*"], $bytes));
        }
    }

    public function isConstructed()
    {
        return $this->isCompound;
    }

    public function isPrimitive()
    {
        return !$this->isConstructed();
    }

    /**
     * An array of TLV objects or an array of bytes.
     * @note isConstructed() will indicate an array of objects.
     *
     * @return array
     */
    public function getContent()
    {
        return $this->content;
    }

    public function getContentAsHex()
    {
        return bin2hex($this->getEncoded());
    }

    public function getContentLength()
    {
        return $this->contentLength;
    }

    public function getNumLengthBytes()
    {
        return $this->numLengthBytes;
    }

    public function getContentType()
    {
        return $this->contentType;
    }

    /**
     * Assert whether this TLV is of $type.
     *
     * @param $type int
     * @return bool
     */
    public function isContentType($type)
    {
        return ($type | $this->getContentType()) === $type;
    }

    /**
     * Determine the content type and pick out the bytes
     * we're interested in.
     * @param $bytes
     */
    private function parseContent(&$bytes)
    {
        switch ($this->getContentType()) {
            case static::INTEGER:
            case static::BOOLEAN:
            case static::EOC:
            case static::REAL:
            case static::OBJECT_IDENTIFIER:
            case static::ENUMERATED:
            case static::UTF8_STRING:
            case static::BIT_STRING:
            case static::CHARACTER_STRING:
            case static::OCTET_STRING:
            case static::RELATIVE_OID:
                $length = $this->getContentLength();
                $content = array_slice($bytes, 0, $length);
                // pad out the remaining missing bytes with 0 bytes.
                if(count($content) < $length){
                    $content = array_merge($content,array_fill(0,$length-count($content),0));
                }
                break;
            case static::SEQUENCE:
                $sequence = [];
                $remainingBytes = count($bytes);
                while ($remainingBytes > 0) {
                    $someBytes = array_slice($bytes, -$remainingBytes);
                    $elem = new static($someBytes);
                    $sequence[] = $elem;
                    $remainingBytes -= (1 + $elem->getContentLength() + $this->getNumLengthBytes());
                }
                $content = $sequence;
                break;
            case static::NULL:
            default:
                $content = null;
        }
        $this->content = $content;

    }

    public function asInteger()
    {
        $bytes = $this->getContent();
        $int = 0;
        foreach($bytes as $byte){
            $int = $int<<8 | $byte;
        }
        return $int;
    }

    public function asString(){
        $bytes = $this->getContent();
        $str = "";
        foreach($bytes as $byte){
            $str .= chr($byte);
        }
        return $str;
    }
}
