// fh project crypto.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	//"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	//"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	//"math"
	//"os"
	//"path/filepath"
	//"runtime"
	//"strings"

	"github.com/wernerd/Skein3Fish/go/src/crypto/threefish"
	"golang.org/x/crypto/twofish"
)

type microHeader struct {
	algo  byte
	iv    []byte
	salt  []byte
	tweak []byte
}

func (mh *microHeader) getLen() uint32 {
	return uint32(2 + len(mh.iv) + len(mh.salt) + len(mh.tweak))
}

func (mh *microHeader) printMe() string {
	s := fmt.Sprintf("algo %d, iv[%s] sa[%s] tw[%s]", mh.algo, hex.EncodeToString(mh.iv), hex.EncodeToString(mh.salt), hex.EncodeToString(mh.tweak))
	return s
}

func (mh *microHeader) byteMe() []byte {
	res := make([]byte, 2)
	_, err := rand.Read(res)
	if err != nil {
		log.Println("Error reading RAND!")
	}
	res[1] = (res[1] & 0xFC) | mh.algo
	res = append(res, mh.iv...)
	res = append(res, mh.salt...)
	if mh.tweak != nil && len(mh.tweak) > 8 {
		res = append(res, mh.tweak...)
	}
	return res
}

func readMicroHeader(tf io.Reader) (*microHeader, error) {
	mh := new(microHeader)
	buf := make([]byte, 256)
	_, err := tf.Read(buf[:2])
	if err != nil {
		return nil, err
	}
	mh.algo = buf[1] & 0x03
	fmt.Println(mh.algo)
	bs, _, ts := getSizes(mh.algo)

	_, err = tf.Read(buf[:bs])
	if err != nil {
		return nil, err
	}
	mh.iv = append(mh.iv, buf[:bs]...)

	_, err = tf.Read(buf[:16])
	if err != nil {
		return nil, err
	}
	mh.salt = append(mh.salt, buf[:16]...)

	if ts > 0 {
		_, err = tf.Read(buf[:ts])
		if err != nil {
			return nil, err
		}
		mh.tweak = append(mh.tweak, buf[:ts]...)
	}

	return mh, nil
}

// deriveKeyBytesFromString derives a key from the password, salt and iteration
// count, returning a []byte of length keylen that can be used as cryptographic
// key. The key is derived based on the method described as PBKDF2 with the
// HMAC variant using the supplied hash function.
func deriveKeyBytesFromString(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

type encryptedHeader struct {
	marker  string
	padding uint16
	filling []byte
}

func (eh *encryptedHeader) getLen() uint32 {
	return uint32(4 + len(eh.filling))
}

func (eh *encryptedHeader) printMe() string {
	s := fmt.Sprintf("%s/%d", eh.marker, eh.padding)
	return s
}

func (eh *encryptedHeader) byteMe() []byte {
	res := []byte(eh.marker)
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, eh.padding)
	res = append(res, buf...)
	res = append(res, eh.filling[:]...)
	return res
}

// cryptoData struct contains all the data (but the key) to describe an algorithm behavior
type cryptoData struct {
	// engine is the basic block ciphering algorithm
	engine                  cipher.Block
	blockSize, keySize      int
	algo                    byte
	iv, salt, filler, tweak []byte
}

// LogMe function allows to log the cryptoData contents (for debug only, insecure)
func (cd *cryptoData) LogMe(key []byte) {
	log.Println("ALGO =", cd.algo, "BS =", cd.blockSize)
	log.Println("PWD  =", hex.EncodeToString(key))
	log.Println("IV   =", hex.EncodeToString(cd.iv))
	log.Println("SALT =", hex.EncodeToString(cd.salt))
	log.Println("TWK  =", hex.EncodeToString(cd.tweak))
}

// Creates a proper microHeader from this data
func (cd *cryptoData) extractMicroHeader() *microHeader {
	mh := new(microHeader)
	mh.algo = byte(cd.algo)
	mh.iv = cd.iv
	mh.salt = cd.salt
	mh.tweak = cd.tweak
	return mh
}

// Creates a proper encrypted Header from this data
func (cd *cryptoData) forgeEncryptedHeader(padding uint16) *encryptedHeader {
	eh := new(encryptedHeader)
	eh.marker = "FH"
	eh.padding = padding
	eh.filling = make([]byte, cd.blockSize-4)
	return eh
}

// getSizes, given an algorithm, returns
// the blocksise which is also the IV size for every algorithm used here
// the keysize
// the tweak size
func getSizes(algo byte) (blockSize int, keySize int, tweakSize int) {
	switch algo {
	case 0:
		blockSize = aes.BlockSize
		keySize = 32
		tweakSize = 0
	case 1:
		blockSize = twofish.BlockSize
		keySize = 32
		tweakSize = 0
	case 2:
		blockSize = 128
		keySize = 128
		tweakSize = 16
	}
	//if *verbose {
	if true {
		log.Println(algo, ": bs =", blockSize, "ks =", keySize, "ts =", tweakSize)
	}
	return
}

// getEngine creates a block cipher, affected by the algorithm, the key, and the tweak
// but not by the iv which is used later when creating the CBCxxCrypter
func getEngine(algo byte, key []byte, tweak []byte) (cipher.Block, error) {
	switch algo {
	case 0:
		return aes.NewCipher(key)
	case 1:
		return twofish.NewCipher(key)
	case 2:
		return threefish.New(key, []uint64{binary.BigEndian.Uint64(tweak[:8]), binary.BigEndian.Uint64(tweak[8:])})
	}
	// if here, the algo was unknown
	return nil, errors.New("Unknown algo")
}

// getCriptoData creates a cryptoData structure and return a pointer to it
// given the algorithm and the password;
// iv, salt, and tweak (when necessary) are randomly created
// as well as a filler for (in case) the last incomplete block

func getCriptoData(algo byte, password *string) (*cryptoData, error) {
	// print the algorithm
	if *verbose {
		log.Println("Algo =", algo)
	}
	// get the sizes of block, key, tweak (iv = block, always for the algo used)
	blockSize, keySize, tweakSize := getSizes(algo)
	// something wrong
	if blockSize == 0 || keySize == 0 {
		return nil, errors.New("Unknown algorithm")
	}
	// initialize the thing to be randomized
	iv := make([]byte, blockSize)
	salt := make([]byte, 16)
	tweak := make([]byte, tweakSize)
	filler := make([]byte, blockSize)

	// fill the IV
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	// fill the salt
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}

	// fill the filler
	_, err = io.ReadFull(rand.Reader, filler)
	if err != nil {
		return nil, err
	}

	// fill the tweak, if needed
	if tweakSize > 0 {
		_, err = io.ReadFull(rand.Reader, tweak)
		if err != nil {
			return nil, err
		}
	}

	// derive a key from the string to byte conversion of the password
	// using the random salt
	key := deriveKeyBytesFromString([]byte(*password), salt, 4096, keySize, sha512.New)

	// creates an engine (need algo, key, tweak)
	engine, err := getEngine(algo, key, tweak)
	// on errors return error
	if err != nil {
		return nil, err
	}
	// create a cryptoData structure
	rtr := &cryptoData{engine: engine, blockSize: blockSize, keySize: keySize, algo: algo, iv: iv, salt: salt, filler: filler, tweak: tweak}
	// log it if necessary
	if *verbose {
		rtr.LogMe(key)
	}
	// return that and no error
	return rtr, nil
}

// getDecriptoData provides criptodata structure for decryption.
// in this case iv, salt, tweak are passed as input together with the key and algo
func getDecriptoData(algo byte, password *string, iv []byte, salt []byte, tweak []byte) (*cryptoData, error) {
	// print the algo
	if *verbose {
		log.Println("Algo =", algo)
	}
	// check that algo is ok an get the lengths of block and key
	blockSize, keySize, _ := getSizes(algo)
	// if unknown algo, exit with error
	if blockSize == 0 || keySize == 0 {
		return nil, errors.New("Unknown algorithm")
	}
	// derive the key in the same way that the 'encrypt' funct did
	key := deriveKeyBytesFromString([]byte(*password), salt, 4096, keySize, sha512.New)
	// get an engine give algo, key, tweak
	engine, err := getEngine(algo, key, tweak)
	// if error, return
	if err != nil {
		return nil, err
	}
	// compile the criptodata structure
	rtr := &cryptoData{engine: engine, blockSize: blockSize, keySize: keySize, algo: algo, iv: iv, salt: salt, filler: nil, tweak: tweak}
	// print it, if needed
	if *verbose {
		rtr.LogMe(key)
	}
	//return it and no error
	return rtr, nil
}
