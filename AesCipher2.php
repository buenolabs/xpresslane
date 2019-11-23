<?php

/**
 * AesCipher
 *
 * Encode/Decode text by password using AES-128-CBC algorithm
 */
class AesCipher
{
    const CIPHER = 'AES-128-CBC';
    const INIT_VECTOR_LENGTH = 16;

    /**
     * Encoded/Decoded data
     *
     * @var null|string
     */
    protected $data;
    /**
     * Initialization vector value
     *
     * @var string
     */
    protected $initVector;
    /**
     * Error message if operation failed
     *
     * @var null|string
     */
    protected $errorMessage;

    /**
     * AesCipher constructor.
     *
     * @param string $initVector        Initialization vector value
     * @param string|null $data         Encoded/Decoded data
     * @param string|null $errorMessage Error message if operation failed
     */
    public function __construct($initVector, $data = null, $errorMessage = null)
    {
        $this->initVector = $initVector;
        $this->data = $data;
        $this->errorMessage = $errorMessage;
    }

    /**
     * Encrypt input text by AES-128-CBC algorithm
     *
     * @param string $secretKey 16/24/32 -characters secret password
     * @param string $plainText Text for encryption
     *
     * @return self Self object instance with data or error message
     */
    public static function encrypt($secretKey, $plainText)
    {
        try {
            // Check secret length
            if (!static::isKeyLengthValid($secretKey)) {
                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");
            }

            // Get random initialization vector
            $initVector = bin2hex(openssl_random_pseudo_bytes(static::INIT_VECTOR_LENGTH / 2));

            // Encrypt input text
            $raw = openssl_encrypt(
                $plainText,
                static::CIPHER,
                $secretKey,
                OPENSSL_RAW_DATA,
                $initVector
            );

            // Return base64-encoded string: initVector + encrypted result
            $result = base64_encode($initVector . $raw);

            if ($result === false) {
                // Operation failed
                return new static($initVector, null, openssl_error_string());
            }

            // Return successful encoded object
            return new static($initVector, $result);
        } catch (\Exception $e) {
            // Operation failed
            return new static(isset($initVector), null, $e->getMessage());
        }
    }

    /**
     * Decrypt encoded text by AES-128-CBC algorithm
     *
     * @param string $secretKey  16/24/32 -characters secret password
     * @param string $cipherText Encrypted text
     *
     * @return self Self object instance with data or error message
     */
    public static function decrypt($secretKey, $cipherText)
    {
        try {
            // Check secret length
            if (!static::isKeyLengthValid($secretKey)) {
                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");
            }

            // Get raw encoded data
            $encoded = base64_decode($cipherText);
            // Slice initialization vector
            $initVector = substr($encoded, 0, static::INIT_VECTOR_LENGTH);
            // Slice encoded data
            $data = substr($encoded, static::INIT_VECTOR_LENGTH);

            // Trying to get decrypted text
            $decoded = openssl_decrypt(
                $data,
                static::CIPHER,
                $secretKey,
                OPENSSL_RAW_DATA,
                $initVector
            );
print($decoded);
            if ($decoded === false) {
                // Operation failed
                return new static(isset($initVector), null, openssl_error_string());
            }

            // Return successful decoded object
            return new static($initVector, $decoded);
        } catch (\Exception $e) {
            // Operation failed
            return new static(isset($initVector), null, $e->getMessage());
        }
    }

    /**
     * Check that secret password length is valid
     *
     * @param string $secretKey 16/24/32 -characters secret password
     *
     * @return bool
     */
    public static function isKeyLengthValid($secretKey)
    {
        $length = strlen($secretKey);

        return $length == 16 || $length == 24 || $length == 32;
    }

    /**
     * Get encoded/decoded data
     *
     * @return string|null
     */
    public function getData()
    {
        return $this->data;
    }

    /**
     * Get initialization vector value
     *
     * @return string|null
     */
    public function getInitVector()
    {
        return $this->initVector;
    }

    /**
     * Get error message
     *
     * @return string|null
     */
    public function getErrorMessage()
    {
        return $this->errorMessage;
    }

    /**
     * Check that operation failed
     *
     * @return bool
     */
    public function hasError()
    {
        return $this->errorMessage !== null;
    }

    /**
     * To string return resulting data
     *
     * @return null|string
     */
    public function __toString()
    {
        return $this->getData();
    }
}


$orderData = '{  
 "merchantsuccessurl":  "http://localhost:8083/g.html",
 "merchantcarturl": "http://localhost:8083/local-bb4.html", 
 "merchantid": "61A91", 
 "secretkey": "76783823219015928676",
 "merchantorderid": "1912",
 "orderdate": "2019-11-21T14:56:11.0Z", 
 "grandtotal":"58", 
 "preshiptotal":"58", 
 "coupon_code":"0", 
 "cgst": "0", 
 "sgst": "0", 
 "coupondiscount":"0", 
 "discount":"0", 
 "subtotal":"58", 
 "total":"58", 
 "currency": "INR",
 "orderitems":[{ 
        "productname":"Fresho Cauliflower", 
        "sku":"1112", 
        "quantity":"1", 
        "productdescription":"Fresho Cauliflower", 
        "unitprice":"58", 
        "discountamount":"0", 
        "discountunitprice":"0", 
        "originalprice":"58", 
        "actualprice":"58",     
        "productimage":"//www.bigbasket.com/media/uploads/p/m/10000074_19-fresho-cauliflower.jpg",
        "merchantproductid":"1112",
        "size": ""
    }],
    "shippingoptions":[{
        "shippingcode":"FLAT_AMT", 
        "shippingname":"Flat Amount", 
        "shippingprice":"5"
        }]
}';

$secretKey = substr("76783823219015928676", 0, 16);
$encrypted = AesCipher::encrypt($secretKey, $orderData);

$encryptedText = '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';

$decrypted = AesCipher::decrypt($secretKey, $encryptedText);

print($decrypted->getData());

#print($encrypted->getData());

