<?php

require_once(__DIR__.'/NetCrypt.php');

use PHPUnit\Framework\TestCase;

final class NetCryptTest extends TestCase
{
    public function testEncNetDecOpenSsl(): void
    {
        $input = __DIR__.'/img.png';
        $output = __DIR__.'/encNetimg.aes';
        $verif = __DIR__.'/verifEncNetDecOpenSsl.png';
        $mykey = 'mySup3rKey';
        $key = substr(hash('sha256', $mykey, true), 0, 16);
        $md5Ori = md5_file($input);
        Marinvs\NetCrypt::encryptFile($input, $mykey, $output);
        // Decrypt
        $data = file_get_contents($output);
        $iv = substr($data, 0, 16);
        $sizeModulo = hexdec(bin2hex(substr($data, 16, 1)));
        $cipherText = substr($data, 17);

        file_put_contents($verif, openssl_decrypt($cipherText, 'AES-256-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv));

        // Remove padding
        if ($sizeModulo !== 0) {
            $ver = file_get_contents($verif);
            $p = 16 - $sizeModulo;
            $ver = substr($ver, 0, strlen($ver) - $p);
            file_put_contents($verif, $ver);
        }

        // file_put_contents(__DIR__.'/decSslimg.txt', $this->formatFile($verif));
        $md5Verif = md5_file($verif);

        $this->assertEquals($md5Ori, $md5Verif);
    }

    public function testEncOpenSslDecNet(): void
    {
        $input = __DIR__.'/img.png';
        $output = __DIR__.'/encSslimg.aes';
        $verif = __DIR__.'/verifEncOpenSslDecNet.png';
        $mykey = 'mySup3rKey';
        $key = substr(hash('sha256', $mykey, true), 0, 16);
        $md5Ori = md5_file($input);

        $iv = openssl_random_pseudo_bytes(16);

        $hexModulo = dechex(filesize($input) % 16);
        // fill to 16 bytes
        while (strlen($hexModulo) < 2) {
            $hexModulo = '0'.$hexModulo;
        }
        $binModulo = hex2bin($hexModulo);

        $cipherText = $iv.$binModulo;
        $inputContent = file_get_contents($input).Marinvs\NetCrypt::getPadding(hexdec($hexModulo));

        $cipherText .= openssl_encrypt($inputContent, 'AES-256-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        file_put_contents($output, $cipherText);
        // Decrypt
        Marinvs\NetCrypt::decryptFile($output, $mykey, $verif);

        $md5Verif = md5_file($verif);
        // file_put_contents(__DIR__.'/decNetimg.txt', $this->formatFile($verif));

        $this->assertEquals($md5Ori, $md5Verif);
    }

    protected function formatFile($file)
    {
        $outContents = file_get_contents($file);
        
        return $this->formatBin($outContents);
    }

    protected function formatBin($binString)
    {
        $ftd = '';
        for ($i = 0; $i < strlen($binString); $i += 16) {
            $ftd .= bin2hex(substr($binString, $i, 16))."\n";
        }

        return $ftd;
    }
}
