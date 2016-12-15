//实现outh算法
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"math/big"
	"strconv"
)

const (
	SHA1 uint8 = iota
	SHA256
	SHA512
)

//生成Hmac的值 (没有问题)
func getHMACData(crypto uint8, keyBytes, textBytes []byte) ([]byte, error) {
	var mac hash.Hash

	switch crypto {
	case SHA1:
		mac = hmac.New(sha1.New, keyBytes)
	case SHA256:
		mac = hmac.New(sha256.New, keyBytes)
	case SHA512:
		mac = hmac.New(sha512.New, keyBytes)
	}
	//根据RFC6238中，对keyBytes没有做特殊的处理， 因此直接使用keyBytes中的原始数据

	_, err := mac.Write(textBytes)
	if err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

func GeneratorTOTPSHA1(key, time string, returnNum int) (string, error) {
	return generatorTOTP(SHA1, key, time, returnNum)
}

func GeneratorTOTPSHA256(key, time string, returnNum int) (string, error) {
	return generatorTOTP(SHA256, key, time, returnNum)
}

func GeneratorTOTPSHA512(key, time string, returnNum int) (string, error) {
	return generatorTOTP(SHA512, key, time, returnNum)
}

//把hex 转换成[]byte （）
func hexStr2Bytes(hexstr string) ([]byte, bool) {
	a := &big.Int{}
	bInt, ok := a.SetString("10"+hexstr, 16)
	if !ok {
		return nil, false
	}
	bArray := bInt.Bytes()
	ret := bArray[1:]
	return ret, true
}

var DIGITS_POWER map[int]int

func init() {
	DIGITS_POWER = make(map[int]int, 9)
	DIGITS_POWER[0] = 1
	DIGITS_POWER[1] = 10
	DIGITS_POWER[2] = 100
	DIGITS_POWER[3] = 1000
	DIGITS_POWER[4] = 10000
	DIGITS_POWER[5] = 100000
	DIGITS_POWER[6] = 1000000
	DIGITS_POWER[7] = 10000000
	DIGITS_POWER[8] = 100000000
}

//key私钥，time偏移时间，return 返回数量
func generatorTOTP(crypto uint8, key, time string, returnNum int) (string, error) {
	var result string
	for len(time) < 16 {
		time = "0" + time
	}
	msg, ok := hexStr2Bytes(time)
	if !ok {
		return "", errors.New("time 无法转化成byte数组")
	}
	k, ok := hexStr2Bytes(key)
	if !ok {
		return "", errors.New("key 无法转换成byte数组")
	}

	hash, err := getHMACData(crypto, k, msg)
	if err != nil {
		return "", err
	}
	offset := int(hash[len(hash)-1] & 0xf)

	binary := (((int)(hash[offset]) & 0x7f) << 24) | (((int)(hash[offset+1]) & 0xff) << 16) | (((int)(hash[offset+2]) & 0xff) << 8) | ((int)(hash[offset+3]) & 0xff)
	otp := binary % DIGITS_POWER[returnNum]
	result = strconv.Itoa(otp)
	for len(result) < returnNum {
		result = "0" + result
	}
	return result, nil
}
