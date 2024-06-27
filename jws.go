package jws

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
)

var Version string = "1.0"

var mac hash.Hash

func generatePayload(userId int) string {
	return fmt.Sprintf("{\"iss:%d,\"exp\":%d}", userId, 1300819380)
}
func generateJoseHeader(typ string, alg string) string {
	return fmt.Sprintf("{\"typ\":\"%s\",\"alg\":\"%s\"}", typ, alg)
}
func hexDecRprToStringRep(src byte) byte {
	// 0 -> 9 are digits
	if src < byte(10) {
		return src + 48
	} else {
		// a -> f 97 - 10
		return src + 87
	}

}
func hexInStringFormat(src []byte) []byte {
	var rslt []byte
	for _, val := range src {
		hexLeft := val & byte(0b11110000) >> 4
		hexRight := val & byte(0b00001111)
		rslt = append(rslt, hexDecRprToStringRep(hexLeft))
		rslt = append(rslt, hexDecRprToStringRep(hexRight))
	}
	return rslt
}
func hexStringRepToDecimalRep(src byte) byte {
	// 0 -> 9 are digits
	if src < byte(58) {
		return src - 48
	} else {
		// a -> f 97 - 10
		return src - 87
	}

}

// Taking in consideration only pair length hexstrings, TODO Add check and error in case length is not pair.
func hexStringToByte(src []byte) []byte {
	var rslt []byte
	for i := 0; i < len(src); i += 2 {
		hexLeft := hexStringRepToDecimalRep(src[i]) << 4
		hexRight := hexStringRepToDecimalRep(src[i+1])
		rslt = append(rslt, hexLeft|hexRight)
	}
	return rslt
}
func Init(key string) {
	mac = hmac.New(sha256.New, []byte(key))
}
func generateHMacSum(message []byte) []byte {
	mac.Write([]byte(message))
	sum := mac.Sum(nil)
	mac.Reset()
	return hexInStringFormat(sum)
}

func verifyHMacSum(message string, sum []byte) (bool, error) {
	if len(sum) != 64 {
		return false, fmt.Errorf("Sum with an unvalid size.")
	}
	xbefore := generateHMacSum([]byte(message))
	x := hexStringToByte(xbefore)
	y := hexStringToByte(sum)
	return hmac.Equal(x, y), nil
}
func GenerateJWSToken(userId int) string {
	// Jose Header
	jose64UrlBase := string(base64UrlEncode(generateJoseHeader("JWT", "HS256")))
	// Payload
	payload64UrlBase := string((base64UrlEncode(generatePayload(userId))))
	// Signature

	signature := generateHMacSum([]byte(jose64UrlBase + "." + payload64UrlBase))
	return fmt.Sprintf("%s.%s.%s", jose64UrlBase, payload64UrlBase, signature)
}
func VerifyJWSToken(message string) bool {
	eles := strings.Split(message, ".")
	if len(eles) != 3 {
		return false
	}
	signature := eles[2]
	result, err := verifyHMacSum(fmt.Sprintf("%s.%s", eles[0], eles[1]), []byte(signature))
	if err != nil {
		return false
	}
	return result
}

// TODO there is some kind of redondance here, i need to check how to fix this.
// TODO function for extraction of the content that is flexible
func GetIdFromJWS(message string) (int, error) {
	if VerifyJWSToken(message) {
		eles := strings.Split(message, ".")
		payloadString, err := base64Decoder(eles[1])
		if err != nil {
			return 0, fmt.Errorf("GetIdFromJWS ::: Error in decoding the Payload [%s]. \n", err)
		}
		idString := strings.Split(strings.Split(payloadString, ",")[0], ":")[1]
		idInt, err := strconv.Atoi(idString)
		if err != nil {
			return 0, fmt.Errorf("GetIdFromJWS ::: Error when converting id to int with [%s]. \n", err)
		}
		return idInt, nil
	} else {
		return 0, fmt.Errorf("GetIdFromJWS ::: Verification of the Token failed.\n")
	}
}

func base64ToDecimal(r rune) byte {
	r_d := byte(r)
	if r_d == 43 {
		return byte(62)
	}
	if r_d == 47 {
		return 63
	}
	if r_d > 96 && r_d < 123 {
		return r_d + 26 - 97
	}
	if r_d > 47 && r_d < 58 {
		return r_d + 52 - 48
	}
	if r_d == 61 {
		return 65
	}
	return r_d - 65

}
func decimalToBase64(d byte) rune {
	// lowercase letters
	if d > 25 && d < 52 {
		return rune(97 - 26 + d)
	}
	//digits
	if d >= 52 && d < 62 {
		return rune(48 + d - 52)
	}
	// +
	if d == 62 {
		return rune(43)
	}
	// /
	if d == 63 {
		return rune(47)
	}
	//uppercase letters
	return rune(65 + d)

}
func base64Encode(utf8String string) []rune {
	//	mappingBase64 := string{"A", "B", "C"}
	utf8Bytes := []byte(utf8String)

	loopSize := len(utf8Bytes) / 3
	rest := len(utf8Bytes) % 3
	var result []rune
	for i := 0; i < loopSize; i++ {
		triplet := utf8Bytes[i*3 : (i+1)*3]
		x0 := (triplet[0] & byte(0b11111100)) >> 2
		x1 := (triplet[0]&byte(0b00000011))<<4 | (triplet[1]&byte(0b11110000))>>4
		x2 := (triplet[1]&byte(0b00001111))<<2 | (triplet[2]&byte(0b11000000))>>6
		x3 := (triplet[2] & byte(0b00111111))
		result = append(result, decimalToBase64(x0), decimalToBase64(x1), decimalToBase64(x2), decimalToBase64(x3))
	}
	if rest == 2 {
		pair := utf8Bytes[len(utf8Bytes)-2 : len(utf8Bytes)]
		x0 := (pair[0] & byte(0b11111100)) >> 2
		x1 := (pair[0]&byte(0b00000011))<<4 | (pair[1]&byte(0b11110000))>>4
		x2 := (pair[1] & byte(0b00001111)) << 2
		result = append(result, decimalToBase64(x0), decimalToBase64(x1), decimalToBase64(x2), rune(61))
	} else if rest == 1 {
		ele := utf8Bytes[len(utf8Bytes)-1]
		x0 := (ele & byte(0b11111100)) >> 2
		x1 := (ele & byte(0b00000011)) << 4
		result = append(result, decimalToBase64(x0), decimalToBase64(x1), rune(61), rune(61))
	}
	return result

}
func base64UrlEncode(utf8String string) string {
	plusRune := rune(43)
	slashRune := rune(47)

	scoreRune := rune(45)
	underscoreRune := rune(95)

	base64result := base64Encode(utf8String)
	for i := 0; i < len(base64result); i++ {
		if base64result[i] == plusRune {
			base64result[i] = scoreRune
		} else if base64result[i] == slashRune {
			base64result[i] = underscoreRune
		}
	}
	return string(base64result)
}

// TODO Add Base64url decoder !
func base64Decoder(base64String string) (string, error) {

	base64Bytes := []byte(base64String)
	var utf8Bytes []byte
	loopSize := int(math.Ceil(float64(len(base64Bytes)) / float64(4)))
	//	rest := len(base64Bytes) % 4

	for i := 0; i < loopSize; i++ {
		quad := base64Bytes[i*4 : (i+1)*4]
		a := base64ToDecimal(rune(quad[0]))
		b := base64ToDecimal(rune(quad[1]))
		c := base64ToDecimal(rune(quad[2]))
		d := base64ToDecimal(rune(quad[3]))
		if a == 0 || b == 0 {
			return "", fmt.Errorf("Invalid base64 string")
		}
		x0 := (a&byte(0b00111111))<<2 | (b&byte(0b00110000))>>4
		utf8Bytes = append(utf8Bytes, x0)
		if c != 65 {
			x1 := (b&byte(0b00001111))<<4 | (c&byte(0b00111100))>>2
			utf8Bytes = append(utf8Bytes, x1)
		} else {
			return string(utf8Bytes), nil
		}
		if d != 65 {
			x2 := (base64ToDecimal(rune(quad[2]))&byte(0b00000011))<<6 | (base64ToDecimal(rune(quad[3])) & byte(0b00111111))
			utf8Bytes = append(utf8Bytes, x2)
		} else {
			return string(utf8Bytes), nil
		}
	}
	return string(utf8Bytes), nil
}
