Example
=======
    <?php
    
    use PHPASN\BER;
    $encoded = "020210";
    $ber = new BER($someencodedstring);
    $ber->isContentType(BER::INTEGER); # => true
    echo $ber->asInteger(); # => 16
    
    