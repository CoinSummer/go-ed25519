/**
 * Created by Goland.
 * Description:
 * User: kailee
 * Date: 2021/5/10 1:26 PM
 */
package go_ed25519

import (
	"fmt"
	"testing"
)

// m/44'/501'/0'/0'
func TestVerifyPath(t *testing.T) {
	tests := []struct{
		id int
		path string
	} {
		{
			0,
			"m/44'/501'/0'/0'",
		},
		{
			1,
			"m/44'/501'/1'/0'",
		},
	}

	for _, test := range tests {
		fmt.Println("test:", test.id)
		err := verifyPath(test.path)
		fmt.Println("err:", err)
	}
}

func TestGenerateMnemonic(t *testing.T) {
	mnemonic, err := GenerateMnemonic()
	fmt.Println("mnemonic:", mnemonic)
	fmt.Println("err:", err)
}

func TestGenerateKey(t *testing.T) {
	words := ``

	pubKey, privateKey, err := GenerateKey(words, "", 0)
	fmt.Println("pubKey:", PubKeyToStr(pubKey))
	fmt.Println("privateKey:", PriKeyToStr(privateKey))
	fmt.Println("err:", err)

}
