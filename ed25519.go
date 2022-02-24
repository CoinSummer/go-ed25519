/**
 * Created by Goland.
 * Description:
 * User: kailee
 * Date: 2021/5/10 12:37 PM
 */
package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/mr-tron/base58"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/tyler-smith/go-bip39"
)

type Key struct {
	key       []byte
	chainCode []byte
}

func entropy() ([]byte, error) {
	randomBytes := make([]byte, 0)
	cpuPercent, _ := cpu.Percent(time.Second, false)
	memory, _ := mem.VirtualMemory()
	diskStatus, _ := disk.Usage("/")

	ioCounters, _ := net.IOCounters(true)
	netWork := ""
	if 0 != len(ioCounters) {
		netWork = strconv.Itoa(int(ioCounters[0].BytesSent + ioCounters[0].BytesRecv))
	}

	cRandBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, cRandBytes); err != nil {
		return []byte{}, err
	}

	randomBytes = append(randomBytes, cRandBytes...)

	if 0 != len(cpuPercent) {
		randomBytes = append(randomBytes, float64ToByte(cpuPercent[0])...)
	}
	randomBytes = append(randomBytes, float64ToByte(memory.UsedPercent)...)
	randomBytes = append(randomBytes, float64ToByte(diskStatus.UsedPercent)...)
	randomBytes = append(randomBytes, []byte(netWork)...)

	entropy := sha256.Sum256(randomBytes)
	return entropy[:16], nil
}

// GenerateMnemonic 生成助记词
func GenerateMnemonic() (string, error) {
	entropyBytes, err := entropy()
	if err != nil {
		return "", err
	}

	mnemonic, err := bip39.NewMnemonic(entropyBytes)
	if err != nil {
		return "", err
	}
	return mnemonic, nil
}

// GenerateKey 生成公钥私钥对
func GenerateKey(mnemonic, password string, index int) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed, err := Seed(mnemonic, password)
	if err != nil {
		fmt.Println("get seed error:", err)
		return nil, nil, err
	}

	pubKey, priKey, err := generateKey(seed, index)
	return pubKey, priKey, err
}

func generateKey(seed []byte, index int) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	key, err := NewKeyFromSeed(seed, index)
	if err != nil {
		return nil, nil, err
	}
	p := key.Seed()
	priKey := ed25519.NewKeyFromSeed(p[:])

	pubKey, err := getPubkey(priKey)

	return pubKey, priKey, nil
}

func Seed(mnemonic, password string) ([]byte, error) {
	seedBytes, err := bip39.NewSeedWithErrorChecking(mnemonic, password)
	if err != nil {
		return nil, err
	}
	return seedBytes, nil
}

// NewKeyFromSeed 根据 seed 生成新的私钥
func NewKeyFromSeed(seed []byte, index int) (*Key, error) {
	walletPath := path(index)
	if err := verifyPath(walletPath); err != nil {
		return nil, err
	}

	key, err := masterKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	elements, err := elementsForPath(walletPath)
	if err != nil {
		return nil, err
	}

	for _, element := range elements {
		// We operate on hardened elements
		hardenedElement := element + hardenedOffset
		key, err = newKeyFromSeed(key, hardenedElement)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func newKeyFromSeed(key *Key, i uint32) (*Key, error) {
	if i < hardenedOffset {
		return nil, ErrUnhardenedElement
	}

	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, i)
	tmp := append([]byte{0x0}, key.key...)
	data := append(tmp, iBytes...)

	_hmac := hmac.New(sha512.New, key.chainCode)
	_, err := _hmac.Write(data)
	if err != nil {
		return nil, err
	}
	sum := _hmac.Sum(nil)
	newKey := &Key{
		key:       sum[0:32],
		chainCode: sum[32:64],
	}
	return newKey, nil
}

func masterKeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("seed must be 64 bytes (passed %d)", len(seed))
	}

	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	_, err := mac.Write(seed)
	if err != nil {
		return nil, err
	}
	result := mac.Sum(nil)

	return &Key{
		key:       result[0:32],
		chainCode: result[32:64],
	}, nil
}

func elementsForPath(path string) ([]uint32, error) {
	elements := strings.Split(path, "/")

	results := make([]uint32, len(elements)-1)

	for i, element := range elements[1:] {
		result, err := strconv.ParseUint(strings.TrimRight(element, "'"), 10, 32)
		if err != nil {
			return nil, err
		}
		// Result must fit in uint32
		if result > MaxPathLen {
			return nil, PathLenOut
		}
		results[i] = uint32(result)
	}

	return results, nil
}

func getPubkey(pri []byte) (ed25519.PublicKey, error) {
	reader := bytes.NewReader(pri)
	pub, _, err := ed25519.GenerateKey(reader)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func path(index int) string {
	return fmt.Sprintf("m/44'/501'/%v'/0'", index)
}

func verifyPath(path string) error {
	// Handle absolute or relative paths
	components := strings.Split(path, "/")
	switch {
	case len(components) == 0:
		return EmptyPath

	case strings.TrimSpace(components[0]) == "":
		return AmbiguousPath

	case strings.TrimSpace(components[0]) == "m":
		components = components[1:]
	}
	// All remaining components are relative, append one by one
	if len(components) == 0 {
		return EmptyPath // Empty relative paths
	}

	return nil
}

// Seed returns a copy of the seed for a derived path.
func (k *Key) Seed() [32]byte {
	var seed [32]byte
	copy(seed[:], k.key[:])
	return seed
}

func float64ToByte(float float64) []byte {
	bits := math.Float64bits(float)
	_bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(_bytes, bits)
	return _bytes
}

func PriKeyToStr(k ed25519.PrivateKey) string {
	return base58.Encode(k)
}

func PriKeyStrToBytes(privateKey string) (ed25519.PrivateKey, error) {
	res, err := base58.Decode(privateKey)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func PubKeyToStr(p ed25519.PublicKey) string {
	return base58.Encode(p[:])
}
