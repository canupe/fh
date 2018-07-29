// fh project main.go
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	//"encoding/binary"
	//"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	//"hash"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// verbose variable is made global to be used by every method avoiding passages
var verbose *bool

func main() {
	// Welcome printing
	log.Println("File Hider 2")
	// Extracts parameters from command line
	// input file: multiple (,) and globbable (*) when input for E, single file when D
	fileList := flag.String("i", "", "Input File(s)")
	// output file(E)/folder(D), defaults to [name of first file].out for E, current working dir when D
	final := flag.String("o", "", "OutputFile")
	// the text password (will be derived to []byte, not just converted)
	cmdlinePwd := flag.String("p", "", "Password")
	// id of the password from the master file (password will be asked to open id)
	fromFilePwd := flag.String("P", "", "Password Id")
	// mode: (E)ncrypt (D)ecript (F)ile master
	mode := flag.String("m", "E", "Mode")
	// if (E) used suboption can be R = raw, 1 = monochrome BMP 8bpp, 4 = multichrome BMP 32bpp
	format := flag.String("f", "1", "Format")
	// verbose flag (insecure)
	verbose = flag.Bool("v", false, "Verbose")
	// keep temporary gz file (the file is shredded but use only for debug)
	keep := flag.Bool("keep", false, "Keep")
	// external file to prepend to the output (must be a BMP file or the D will fail!)
	extra := flag.String("e", "", "Extra")
	// external file to mix with the output (must be a BMP file)
	extra2 := flag.String("eb", "", "Blend")
	// algorithm to use 0 = AES256; 1 = twofish256; 2 = threefish 1024
	algoInt := flag.Int("a", 0, "Algo")
	// Master key file
	keyfile := flag.String("fn", "", "Archive filename")
	// Parse the flags
	flag.Parse()
	// if E/D just check the input file is given
	if strings.Index("ED", *mode) >= 0 {
		if len(*fileList) == 0 {
			flag.Usage()
			return
		}
	} else {
		// if F launch Master File Manager
		if *mode == "F" {
			manageMF(*keyfile)
			return
		}
		// else print usage and exit
		flag.Usage()
		return
	}
	// Here we are necessarly E or D
	// cmd line pwd or entry in master key file must be specified
	if len(*cmdlinePwd) == 0 && len(*fromFilePwd) == 0 {
		log.Println("Password not provided")
		flag.Usage()
		return
	}
	if len(*cmdlinePwd) > 0 && len(*fromFilePwd) > 0 {
		log.Println("Use 'p' or 'P'")
		flag.Usage()
		return
	}
	// This pointer variable will hold the password to E/D
	var password *string
	if len(*cmdlinePwd) > 0 {
		// Pwd has been provided 'as is'
		password = cmdlinePwd
	}
	if len(*fromFilePwd) > 0 {
		// Pwd must be retrieved from master file
		// Open the file (which includes asking password)
		km, kpath, _, err := openMasterFile(*keyfile)
		// if something wrong log and exit
		if err != nil {
			log.Println(err)
			return
		}
		// Print how many keys found
		log.Println(len(km), "keys found in", kpath)
		// check in the map
		inside, ok := km[*fromFilePwd]
		if ok {
			// if found, set the password to that
			password = &inside
		} else {
			// if not, exit
			log.Println("No registered password in the master file", kpath)
			return
		}
	}
	if len(*extra) > 0 && len(*extra2) > 0 {
		log.Println("-e and -eb cannot be used together")
		flag.Usage()
		return
	}
	// algo is better as byte
	algo := byte(*algoInt)
	// fileArray will contain the list of files to zip and then encrypt in case E
	// or the one file to decrypt in case D
	fileArray := make([]string, 0)
	if *mode == "E" {
		//first, split on the ','
		for _, part := range strings.Split(*fileList, ",") {
			//for each one, glob (expand) it against the filesystem content
			nf, err := filepath.Glob(part)
			if err != nil {
				// on error, exit
				log.Println("Cannot understand", part)
				return
			}
			// append everything to the file array
			fileArray = append(fileArray, nf...)
		}
	} else {
		// file array is the i=[....] string without further elaboration
		fileArray = append(fileArray, *fileList)
	}
	if len(fileArray) == 0 {
		// if no files, log message and exit
		log.Println("Cannot find any valid file")
		return
	}
	// print input files
	log.Println("input file(s):", fileArray)
	if len(*final) == 0 {
		if *mode == "E" {
			// if not specified, set to [name of first file].out
			base := strings.TrimSuffix(fileArray[0], filepath.Ext(fileArray[0]))
			*final = base + ".out"
		}
		if *mode == "D" {
			// if not specified, files will be decrypted+extracted in current working folder
			*final = "."
		}
	}
	// some printing
	if *mode == "E" {
		log.Println("Encrypting to", *final, "format =", *format)
	} else {
		log.Println("Decrpyting in", *final)
	}

	if *mode == "E" {
		// delete output file, in case it exists
		err := checkAndDelete(*final)
		if err != nil {
			log.Println(err)
			return
		}
		// payload is first compressed, the encrypted.
		// Compression is done on a temporary file : "_fh_.gz"
		fnzip := "_fh_.gz"
		if !*keep {
			// be sure to destroy at the end with shredding unless keep flag is set
			defer destroy(fnzip)
		}
		// call a function with all the files to zip them all
		zipfileLen, err := zipFilesAndCheck(fileArray, fnzip)
		// if something wrong log and exit
		if err != nil {
			log.Println(err)
			return
		}

		// create cryptodata on the algorithm chosen and on the password
		cryda, err := getCriptoData(algo, password)
		// if something wrong log and exit
		if err != nil {
			log.Println(err)
			return
		}

		// encryption is done on a second temporary file because the user
		// may want to hide in different output formats, so the
		// final name chosen by user is still not ready to be used
		destinationForCBCFileName := "_fh_.e1"
		if !*keep {
			// defer the shredding of that file
			defer destroy(destinationForCBCFileName)
		}

		// Start preparing the "base" of output file, passing
		// The file name
		// The format
		// The crypto data (has to be put in header)
		// The size of the data to encrypt
		eh, err := prepareOutputFile(destinationForCBCFileName, *format, cryda, zipfileLen)
		if err != nil {
			log.Println(err)
			return
		}
		// eh contains a signature (FH) and the needed padding at the end
		// some of this padding is block padding, some may be BMP padding
		fmt.Println("Obtained encrypted header", eh.printMe())

		// Open the file containing the data to encrypt
		// Whose name will be of course the temporary zip file name "_fh_.gz"
		sourceForCBC, err := os.Open(fnzip)
		// if something wrong log and exit
		if err != nil {
			log.Println(err)
			return
		}
		// defer its closing
		defer sourceForCBC.Close()
		// This will Encrypt the input data from the Reader into the destinationForCBCFileName file
		// according to crypto data contained in cryda
		err = CBCEncryptToFile(eh, sourceForCBC, destinationForCBCFileName, cryda)
		// if something wrong, log and exit
		if err != nil {
			log.Println(err)
			return
		}
		// do that final padding (block padding to be skipped, already done in crypting)
		paddingNeeded := int(eh.padding - uint16(getPadLen(zipfileLen, uint32(cryda.blockSize))))
		if paddingNeeded > 0 {
			if *verbose {
				log.Println("last padding:", paddingNeeded)
			}
			err = finalPad(destinationForCBCFileName, paddingNeeded)
		}
		// if something wrong, log and exit
		if err != nil {
			log.Println(err)
			return
		}
		// Now, deal with the 'prepend' or 'embed' option
		log.Println("Finalizing", *final)
		err = prependOrBlendOrRename(destinationForCBCFileName, *extra, *extra2, *final)
		// if something wrong, log and exit
		if err != nil {
			log.Println(err)
			return
		}
	} else {
		//(D)ecrypting
		// First of all, check if the source is a 'blend' and in case, deblend
		// Assuming to act on file marked as input
		todecrypt := fileArray[0]
		// check if it is a blend
		isblend, err := isBlended(fileArray[0])
		if err != nil {
			log.Println(err)
			return
		}
		if isblend {
			// if yes, sblend to _fh_.bmp
			log.Println("Extracting temporary file")
			todecrypt = "_fh_.d1"
			err := sblend(fileArray[0], todecrypt)
			if err != nil {
				log.Println("Error de-blending file:", err)
				return
			}
			// and mark for delete
			if !*keep {
				defer destroy(todecrypt)
			}
		} else {
			// let's see if is preprended
			isprepend, err := isPrepended(fileArray[0])
			if err != nil {
				log.Println(err)
				return
			}
			if isprepend {
				// if yes, sprepend to _fh_.bmp
				log.Println("Separating temporary file")
				todecrypt = "_fh_.d1"
				err := detach(fileArray[0], todecrypt)
				if err != nil {
					log.Println("Error separating file:", err)
					return
				}
				// and mark for delete
				if !*keep {
					defer destroy(todecrypt)
				}
			}
		}
		// ok now 'todecrypt' points to the encrypted file after de-masquerading
		// open it to work with the reader
		todecryptf, err := os.Open(todecrypt)
		if err != nil {
			log.Println(err)
			return
		}
		defer todecryptf.Close()
		// we need the size
		fi, err := todecryptf.Stat()
		if err != nil {
			log.Println(err)
			return
		}
		// analyze file and extract headers
		// actually the only relevant information is in mh
		mh, bh, dh, skippedBytes, err := detectFileFormat(todecryptf, true)
		if err != nil {
			log.Println(err)
			return
		}
		// detectFileFormat reads up to the start of encrypted material
		lenOfDataAvailableInSource := uint32(fi.Size()) - skippedBytes
		if *verbose {
			if bh != nil {
				log.Println("BH=", bh.printMe())
			}
			if dh != nil {
				log.Println("DH=", dh.printMe())
			}
			// mh always != nil if err == nil
			log.Println("MH=", mh.printMe())
			log.Println("Skipped bytes due to header :", skippedBytes)
			log.Println("File len =", fi.Size(), "remaining len =", lenOfDataAvailableInSource)
		}
		// now we should have everything to rebuild the crypto data
		cryda, err := getDecriptoData(mh.algo, password, mh.iv, mh.salt, mh.tweak)
		if err != nil {
			log.Println(err)
			return
		}
		// Output file name (temporary) for parking the ready-to-unzip decrypted data
		destinationForCBCFileName := "_fh2.gz"
		if !*keep {
			// defer the shredding of that file
			defer destroy(destinationForCBCFileName)
		}
		// decrypt in that file
		err = CBCDecryptToFile(todecryptf, destinationForCBCFileName, cryda, lenOfDataAvailableInSource)
		if err != nil {
			log.Println(err)
			return
		}
		// obtained decrypted data must be unzipped
		if *verbose {
			log.Println("Unzipping")
		}
		// do that final unzipping
		list, err := unzipFile(destinationForCBCFileName, *final)
		// if something wrong, log and exit
		if err != nil {
			log.Println(err)
			return
		}
		// and print the result, which will be the list of unzipped files
		log.Println("Result:", list)
	}
}

// finalPad pads the fname file with padLen random bytes
// returns error is something goes wrong
func finalPad(fname string, padLen int) error {
	// open file in write+append
	outFile, err := os.OpenFile(fname, os.O_WRONLY|os.O_APPEND, 0666)
	// if error, return it
	if err != nil {
		return err
	}
	// defer the closing
	defer outFile.Close()
	// create a long enough random-filled byte array
	padBlock := make([]byte, padLen)
	if _, err = io.ReadFull(rand.Reader, padBlock); err != nil {
		// return if error happens
		return err
	}
	// apped the byte array
	_, err = outFile.Write(padBlock)
	if err != nil {
		// return if error happens
		return err
	}
	// return no error
	return nil
}

// CBCDecryptToFile is a wrapper for CBCEncrypt that accepts a file name as output file
func CBCDecryptToFile(originFile io.Reader, outfile string, cryda *cryptoData, dataAvailable uint32) error {
	// filler nil means DECRYPTING, and in this case the output file must be created
	// (will contain the derypted data)
	tflag := os.O_CREATE | os.O_TRUNC
	// open the file with the correct mode
	writeHere, err := os.OpenFile(outfile, tflag, 0666)
	// return error if error
	if err != nil {
		log.Println("Error CBCDecryptToFile1")
		return err
	}
	//defer the closing
	defer writeHere.Close()
	// and return the values of the wrapped function called with a Writer instead of a file name
	return CBCDecrypt(originFile, writeHere, cryda, dataAvailable)
}

// CBCEncryptToFile is a wrapper for CBCEncrypt that accepts a file name as output file
func CBCEncryptToFile(eh *encryptedHeader, originFile io.Reader, outfile string, cryda *cryptoData) error {
	// append mode if ENCRYPTING because file header has already been written
	// and we must append
	tflag := os.O_WRONLY | os.O_APPEND
	// open the file with the correct mode
	writeHere, err := os.OpenFile(outfile, tflag, 0666)
	// return error if error
	if err != nil {
		log.Println("Error CBCEncryptToFile1")
		return err
	}
	//defer the closing
	defer writeHere.Close()
	// and return the values of the wrapped function called with a Writer instead of a file name
	return CBCEncrypt(eh, originFile, writeHere, cryda)
}

// CBCEncrypt perform Encryption if cryptodata.filler (cryda.filler) is full and
// decryption if empty
// if decrypting, dataLen is important because it tells where the data finishes and the
// padding starts, otherwise it is not used
// data to pass in the engine is reader from the io.Reader and written to the io.Writer
func CBCEncrypt(eh *encryptedHeader, originFile io.Reader, writeHere io.Writer, cryda *cryptoData) error {
	// declares a ciphers and using the engine inside crypto data
	// wraps it into a CBC encrypter or decrypter (IV is needed here)
	var worker cipher.BlockMode
	worker = cipher.NewCBCEncrypter(cryda.engine, cryda.iv)
	// write the header inside the encrypted part. It is block-multiple
	firstBlock := eh.byteMe()
	worker.CryptBlocks(firstBlock, firstBlock)
	n, err := writeHere.Write(firstBlock)
	if err != nil {
		return err
	}
	if *verbose {
		log.Println(n, "bytes of eh written:", eh.printMe())
		log.Println("Padding after data will be of", eh.padding)
	}
	// how many bytes have been read
	bytesAlreadyRead := uint32(0)
	// create a block variable to host blocks (4096 bytes)
	// must be multiple of block length, 4096 is multiple of every reasonable block size
	block := make([]byte, 4096)
	blockPadUsed := 0
	// until break-ed
	for {
		// read a block
		n, err := originFile.Read(block)
		// if EOF, obviously, break the cycle
		if err != nil {
			if err == io.EOF {
				log.Println("EOF Found, bytes read this call:", n, "total :", bytesAlreadyRead)
				break
			}
			// if error but not EOF, exit with error
			return err
		}
		// increment read bytes
		bytesAlreadyRead = bytesAlreadyRead + uint32(n)
		// ifdata read is not multiple of block len
		if n%cryda.blockSize > 0 {
			// calculate how many pad bytes we need
			blockPadUsed = cryda.blockSize - (n % cryda.blockSize)
			// print it
			if *verbose {
				log.Println("Chunk of size", n, "needs padding of", blockPadUsed)
			}
			// append enough random rubbish
			block = append(block, cryda.filler[:blockPadUsed]...)
			// record we have read more bytes (and the block data)
			n = n + blockPadUsed
		}
		// crypt the block up to byte n
		worker.CryptBlocks(block[:n], block[:n])
		// write what needs to be written
		_, err = writeHere.Write(block[:n])
		// on error, return error
		if err != nil {
			return err
		}

	}
	// print (always) how many bytes have been E/D
	log.Println(bytesAlreadyRead, "bytes encoded,", blockPadUsed, "padding used")
	// return no error
	return nil
}

// CBCEncrypt perform Encryption if cryptodata.filler (cryda.filler) is full and
// decryption if empty
// if decrypting, dataLen is important because it tells where the data finishes and the
// padding starts, otherwise it is not used
// data to pass in the engine is reader from the io.Reader and written to the io.Writer
func CBCDecrypt(originFile io.Reader, writeHere io.Writer, cryda *cryptoData, dataAvailable uint32) error {
	// the first block, which must be decrypted, is the 'encrypted header'
	// containing FH, the padding used, and filling up to blocksize
	// print the len of file
	if *verbose {
		log.Println("Data available in reader =", dataAvailable)
		log.Println("Block size =", cryda.blockSize)
	}

	// creating the worker
	worker := cipher.NewCBCDecrypter(cryda.engine, cryda.iv)
	// buffer to host the first block
	bytesOfEh := make([]byte, cryda.blockSize)
	// read it
	n, err := originFile.Read(bytesOfEh)
	if err != nil {
		return err
	}
	if n != cryda.blockSize {
		return errors.New(fmt.Sprintf("Cannot read first % encrypted bytes", cryda.blockSize))
	}
	// decrypt it
	worker.CryptBlocks(bytesOfEh, bytesOfEh)
	if string(bytesOfEh[:2]) != "FH" {
		log.Println("Wrong file format")
		return err
	}
	// recover the padding
	padding := uint32(bytesOfEh[3])*256 + uint32(bytesOfEh[2])
	if *verbose {
		log.Println(cryda.blockSize, "bytes read in 'encrypted header'")
		log.Println("TOTAL PADDING is", padding, "so", padding, "bytes are not of interest")
	}
	// stores how many useful bytes are to be read
	missingUsefulBytes := dataAvailable - padding - uint32(cryda.blockSize)
	// remember this number
	usefulBytesAfterHeader := missingUsefulBytes
	if *verbose {
		log.Println("Useful bytes from now are", usefulBytesAfterHeader)
	}

	// how many bytes have been read
	bytesAlreadyRead := uint32(0)
	// create a block variable to host blocks (4096 bytes)
	// must be multiple of block length, 4096 is multiple of every reasonable block size
	block := make([]byte, 4096)
	// until break-ed
	for {
		// read a block
		n, err := originFile.Read(block)
		// if EOF, obviously, break the cycle
		if err != nil {
			if err == io.EOF {
				log.Println(bytesAlreadyRead, "read and EOF, exit, bytes read on this call :", n)
				break
			}
			// if error but not EOF, exit with error
			return err
		}
		// increment read bytes
		bytesAlreadyRead = bytesAlreadyRead + uint32(n)
		// we have passed the limit of useful data (we have read some padding)
		if bytesAlreadyRead > usefulBytesAfterHeader {
			// print it
			if *verbose {
				log.Println("bytes read =", n, "bytesAlreadyRead =", bytesAlreadyRead, "usefulBytesAfterHeader =", usefulBytesAfterHeader, ": this is last block")
			}
			interestingBytes := usefulBytesAfterHeader - (bytesAlreadyRead - uint32(n))
			interestingBytesPadded := getPaddedLen(interestingBytes, uint32(cryda.blockSize))
			// decrypt the block (the part read)
			if *verbose {
				log.Println("Interesting bytes are :", interestingBytes, "padded to", interestingBytesPadded)
			}
			worker.CryptBlocks(block[:interestingBytesPadded], block[:interestingBytesPadded])
			// write the useful part
			if *verbose {
				log.Println("Writing the last bytes :", interestingBytes)
			}
			_, err := writeHere.Write(block[:interestingBytes])
			if err != nil {
				return err
			}
			return nil
		}
		// decrypt the block up to byte n (which should always be 4096)
		if n != 4096 {
			log.Println("Not a 4096 block, expecting EOF next round")
		}
		worker.CryptBlocks(block[:n], block[:n])
		// write
		_, err = writeHere.Write(block[:n])
		// on error, return error
		if err != nil {
			return err
		}
	}
	// print (always) how many bytes have been E/D
	log.Println(bytesAlreadyRead, "bytes en/de-coded")
	// return no error
	return nil
}

// prepareOutputFile is a wrapper for prepareOutputWriter accepting a file name as first paramete instead of a writer
func prepareOutputFile(fname string, format string, cryda *cryptoData, payloadLen uint32) (*encryptedHeader, error) {
	// creates a file from the name
	tf, err := os.Create(fname)
	// on error, return error
	if err != nil {
		return nil, err
	}
	// defer the closing
	defer tf.Close()
	// return the output of the wrapped function
	return prepareOutputWriter(tf, format, cryda, payloadLen)
}

func testFindBmpDataForSize() {
	higher := uint32(0)
	for t := uint32(1); t < 3000000000; t++ {
		for b := uint32(1); b <= 1; b += 3 {
			if t%10000000 == 0 {
				fmt.Println("...", t/1000000)
			}
			r, c := findBmpDataForSize(t, 0, 16, b, false)
			if r*c*b < t {
				fmt.Println(r, "*", c, "*", b, "<", t)
			} else {
				if r*c*b-t > higher {
					higher = r*c*b - t
					if higher > 65000 {
						fmt.Println(r, "*", c, "*", b, "-", t, "=", higher)
					}
				}
			}
			if (c*b)%4 != 0 {
				fmt.Println(r, "*", c, "-", t, "not 4x")
			}
		}
	}
	fmt.Println(higher)
}

func findBmpDataForSize(dataLen uint32, extraDataLen uint32, blockSize uint32, bypp uint32, dbg bool) (uint32, uint32) {
	if dbg {
		log.Printf("Data to fit in bmp is %d (encrypted, padded at %d) + extra %d plain \n", dataLen, blockSize, extraDataLen)
	}
	// then padded to blocksize
	blockPadNeeded := getPadLen(dataLen, blockSize)
	paddedSizeOfDataToEncrypt := dataLen + blockPadNeeded
	fullDataToPack := paddedSizeOfDataToEncrypt + extraDataLen
	if dbg {
		log.Printf("blockPadNeeded = %d, paddedSizeOfDataToEncrypt = %d, fullDataToPack = %d\n", blockPadNeeded, paddedSizeOfDataToEncrypt, fullDataToPack)
	}
	// how many pixels? (in the WORST case we are dividing by 4, and blocksize is always 16x)
	lenInPixMultipleOfBpp := getPaddedLen(fullDataToPack, bypp) / bypp
	if dbg {
		log.Printf("In pixel (%dbpp) is %d\n", bypp, lenInPixMultipleOfBpp)
	}
	// potential num of columns, rounded up
	col := uint32(math.Sqrt(float64(lenInPixMultipleOfBpp)))
	// col (in bytes) must be a 4x
	col = getPaddedLen(col, 4/bypp)
	row := lenInPixMultipleOfBpp / col
	if row*col != lenInPixMultipleOfBpp {
		row = row + 1
	}
	if dbg {
		log.Printf("Result is %d rows X %d cols for a total size of %d", row, col, row*col*bypp)
	}
	return row, col
}

func getPadLen(originalLen uint32, blockSize uint32) uint32 {
	if originalLen%blockSize == 0 {
		return 0
	}
	return blockSize - originalLen%blockSize
}

func getPaddedLen(originalLen uint32, blockSize uint32) uint32 {
	return originalLen + getPadLen(originalLen, blockSize)
}

// prepareOutputWriter prepares the output when encrypting (not called in mode D)
// and prepares the BMP header making a quite square bmp and adjusting other parameters
// tf is where to write
// format is the output format (RAW, 8bb, 24bpp)
// cryptodata is the cryptodata container
// payloadLen is the len of the data to encrypt
// returns how much the data needs to be padded to be a valid BMP and the error, in case

func prepareOutputWriter(tf io.Writer, format string, cryda *cryptoData, payloadLen uint32) (*encryptedHeader, error) {
	// detect how much data, padding included, needs to be encrypted
	encryptedLen := payloadLen
	// extract a public header from crpytoData
	mh := cryda.extractMicroHeader()
	eh := cryda.forgeEncryptedHeader(0)
	if format == "R" {
		// final format is [public header]|E(padToBlock(encrypted header|realpayload))
		encryptedLen = getPaddedLen(eh.getLen()+payloadLen, uint32(cryda.blockSize))
		eh.padding = uint16(encryptedLen - (eh.getLen() + payloadLen))
		if *verbose {
			log.Printf("Input size = %d, eh = %d, needs pad for x%d of %d\n", payloadLen, eh.getLen(), cryda.blockSize, eh.padding)
			log.Println("Calculated eh :", eh.printMe())
		}
		if *verbose {
			log.Println("Writing mh", mh.printMe(), mh.getLen(), "bytes")
		}
		_, err := tf.Write(mh.byteMe())
		if err != nil {
			return nil, err
		}
		return eh, nil
	}
	if format == "1" || format == "4" {
		bypp := uint32(format[0] - '0')
		if *verbose {
			log.Println("Data to encrypt is", payloadLen, "+ eh :", eh.getLen(), "prepended with mh :", mh.getLen(), "block size is", cryda.blockSize)
		}
		row, col := findBmpDataForSize(payloadLen+eh.getLen(), mh.getLen(), uint32(cryda.blockSize), bypp, *verbose)
		bmpRawSize := row * col * bypp
		eh.padding = uint16(bmpRawSize - (mh.getLen() + eh.getLen() + payloadLen))
		if *verbose {
			log.Printf("Bmp Raw Size Will be %d (%dx%dx%d)\n", bmpRawSize, row, col, bypp)
			log.Printf("Bmp data will be mh (%d bytes in plain)\n", mh.getLen())
			log.Printf("                 eh + data = %d + %d = %d\n", eh.getLen(), payloadLen, eh.getLen()+payloadLen)
			log.Printf("So the TOTAL padding will be %d\n", eh.padding)
		}
		// create the two parts of BMP header
		bh := new(bmpHeader)
		// basic values
		bh.marker = "BM"
		bh.r1r2 = 0
		bh.offset = 54 // base case when no color map needed
		colorMapSize := uint32(1024)
		if bypp == 1 {
			bh.offset = 54 + colorMapSize
		}
		bh.bmpSize = bh.offset + bmpRawSize
		dh := new(dibHeader)
		dh.algo = 0   // no more used
		dh.blkpad = 0 // no more used
		dh.marker = string([]byte{0, 0})
		dh.bitspp = uint16(bypp * 8)
		dh.colors = 0
		dh.compre = 0
		dh.height = row
		dh.width = col
		dh.hrzres, dh.vrtres = 3799, 3799
		dh.planes = 1
		dh.rawsiz = bmpRawSize
		dh.typeLen = 40
		if *verbose {
			log.Println("Writing bh :", bh.printMe())
		}
		_, err := tf.Write(bh.byteMe())
		if err != nil {
			return nil, err
		}
		if *verbose {
			log.Println("Writing dh :", dh.printMe())
		}
		_, err = tf.Write(dh.byteMe())
		if err != nil {
			return nil, err
		}
		if bypp == 1 {
			if *verbose {
				log.Println("Writing color map")
			}
			colors := bytes.Repeat([]byte{200, 0, 0, 0}, 256)
			_, err = tf.Write(colors)
			if err != nil {
				return nil, err
			}
		}
		if *verbose {
			log.Println("Writing mh :", mh.printMe())
		}
		_, err = tf.Write(mh.byteMe())
		if err != nil {
			return nil, err
		}
		return eh, nil
	}
	return nil, errors.New("Unknown base format")
}

func detectFileFormat(tf io.ReadSeeker, dbg bool) (*microHeader, *bmpHeader, *dibHeader, uint32, error) {
	firstTwoBytes := make([]byte, 2)
	_, err := tf.Read(firstTwoBytes)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	_, err = tf.Seek(0, 0)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if string(firstTwoBytes) == "BM" {
		bh, err := readBmpHeader(tf)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		dh, err := readDibHeader(tf)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if dbg {
			log.Println("Offset is", bh.offset)
		}
		n, err := tf.Seek(int64(bh.offset), 0)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if dbg {
			log.Println("Offset skipped", n)
		}
		mh, err := readMicroHeader(tf)
		if err != nil {
			return nil, nil, nil, 0, err
		}
		if dbg {
			log.Println(mh.getLen(), "bytes of mh read")
		}
		return mh, bh, dh, uint32(bh.offset) + mh.getLen(), nil
	}
	// not a fake BMP, assume microheader (which is anonymous) is at the start
	mh, err := readMicroHeader(tf)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return mh, nil, nil, mh.getLen(), err
}

// These functions regard the password file management
func readFileIntoMap(fn string, pwd *string, dbg bool) (map[string]string, error) {
	// Input file preparation
	sourceForCBC, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer sourceForCBC.Close()
	fi, err := sourceForCBC.Stat()
	if err != nil {
		return nil, err
	}
	mh, _, _, skippedBytes, err := detectFileFormat(sourceForCBC, dbg)
	if err != nil {
		return nil, err
	}
	// detectFileFormat reads up to the start of encrypted material
	lenOfDataAvailableInSource := uint32(fi.Size()) - skippedBytes
	if dbg {
		// mh always != nil if err == nil
		log.Println("MH=", mh.printMe())
		log.Println("Skipped bytes due to header(s) :", skippedBytes)
		log.Println("File len =", fi.Size(), "remaining len =", lenOfDataAvailableInSource)
	}
	// now we should have everything to rebuild the crypto data
	cryda, err := getDecriptoData(mh.algo, pwd, mh.iv, mh.salt, mh.tweak)
	if err != nil {
		return nil, err
	}
	// we will decode in a buffer in memory
	writeHere := new(bytes.Buffer)
	err = CBCDecrypt(sourceForCBC, writeHere, cryda, lenOfDataAvailableInSource)
	if err != nil {
		return nil, err
	}
	if *verbose {
		fmt.Println(writeHere.Len(), "bytes read")
		fmt.Println(string(writeHere.Bytes()))
	}
	kmap := make(map[string]string, 10)
	err = json.Unmarshal(writeHere.Bytes(), &kmap)
	if err != nil {
		return nil, err
	}
	return kmap, nil
}

func openMasterFile(keyfile string) (map[string]string, *string, *string, error) {
	kfn, kfe, err := locateKeyFile(keyfile)
	if err != nil {
		log.Println(err)
		return nil, nil, nil, err
	}
	if *verbose {
		log.Println("PWD file =", kfn, kfe)
	}
	kpw := askSomething("Provide Master Key for <"+kfn+"> :", true)
	if err != nil {
		log.Println(err)
		return nil, nil, nil, err
	}
	kmap := make(map[string]string, 0)
	if !kfe {
		return kmap, &kfn, kpw, nil
	}
	kmap, err = readFileIntoMap(kfn, kpw, *verbose)
	if err != nil {
		log.Println(err)
		return nil, nil, nil, err
	}
	return kmap, &kfn, kpw, nil
}

func manageMF(keyfile string) {
	kfn, kfe, err := locateKeyFile(keyfile)
	if err != nil {
		log.Println(err)
		return
	}
	if *verbose {
		log.Println("PWD file =", kfn, kfe)
	}
	var keypass string
	kmap := make(map[string]string, 10)
	for {
		fmt.Println("Provide Master Key:")
		fmt.Scanln(&keypass)
		if len(keypass) == 0 {
			continue
		}
		if kfe {
			kmap, err = readFileIntoMap(kfn, &keypass, *verbose)
			if err != nil {
				if *verbose {
					log.Println(err)
				}
				log.Println("Password is not correct, or password file corrupted")
				continue
			}
			break
		}
		break
	}

	// in any case now I have the map
	for {
		// which operation
		fmt.Printf("A - Add Key\nR - Remove Key\nL - List\nS - Save\nC - Change PWD\nE - Erase\nQ - Quit\nYour Choice:")
		var op string
		fmt.Scanf("%s\n", &op)
		if len(op) != 1 {
			continue
		}
		switch op {
		case "Q":
			return
		case "A":
			var id, key string
			fmt.Println("Adding Key")
			fmt.Printf("Key Code:")
			fmt.Scanln(&id)
			fmt.Printf("Key Data:")
			fmt.Scanln(&key)
			fmt.Printf("Adding key for %s (%d) chars\n", id, len(key))
			kmap[id] = key
		case "R":
			var id string
			fmt.Println("Delete Key")
			fmt.Printf("Key Code:")
			fmt.Scanln(&id)
			delete(kmap, id)
		case "E":
			var yn string
			fmt.Println("Erase Master Key file")
			fmt.Printf("Confirm (Y/n)?")
			fmt.Scanln(&yn)
			if yn == "Y" {
				err := destroy(kfn)
				if err != nil {
					fmt.Println("Cannot delete", keyfile, err)
				}
			}
		case "C":
			var nk1, nk2 string
			fmt.Println("Change Master Key")
			fmt.Printf("New Key:")
			fmt.Scanln(&nk1)
			fmt.Printf("Confirm Key:")
			fmt.Scanln(&nk2)
			if nk1 == nk2 && len(nk1) > 0 {
				fmt.Println("Password changed, remember to save")
				keypass = nk1
			} else {
				fmt.Println("invalid key")
			}
		case "L":
			fmt.Println("Current keys:")
			for k, d := range kmap {
				fmt.Println(k, "=", d)
			}
		case "S":
			kfile, err := os.Create(kfn)
			if err != nil {
				fmt.Println("Cannot create", kfn)
			}
			defer kfile.Close()
			encoded, err := json.Marshal(kmap)
			if err != nil {
				log.Println(err)
				fmt.Println("Encoding error")
				break
			}
			bi := bytes.NewReader(encoded)
			cryda, err := getCriptoData(2, &keypass)
			if err != nil {
				log.Println(err)
				break
			}
			eh, err := prepareOutputFile(kfn, "1", cryda, uint32(len(encoded)))
			if err != nil {
				log.Println(err)
				break
			}
			err = CBCEncryptToFile(eh, bi, kfn, cryda)
			if err != nil {
				log.Println(err)
				break
			}
			blockPaddingAlreadyDone := getPadLen(eh.getLen()+uint32(len(encoded)), uint32(cryda.blockSize))
			paddingNeeded := int(eh.padding - uint16(blockPaddingAlreadyDone))
			if *verbose {
				log.Println("TOTAL Padding is", eh.padding)
				log.Println("Already done block padding is", blockPaddingAlreadyDone, "which is the padding to", cryda.blockSize, "of", eh.getLen()+uint32(len(encoded)))
				log.Println("Remaining padding needed (random bytes at end of file to complete the BMP) is", paddingNeeded)
			}
			// do that final padding (block padding to be skipped, already done in crypting)
			if paddingNeeded > 0 {
				if *verbose {
					log.Println("last padding:", paddingNeeded)
				}
				err = finalPad(kfn, paddingNeeded)
				if err != nil {
					log.Println(err)
					break
				}
			}
		default:
			fmt.Println("Unknown option :", op)
		}
	}

}

func locateKeyFile(fname string) (string, bool, error) {
	if len(fname) == 0 {
		_, execLine, _, _ := runtime.Caller(0)
		execPath := filepath.Dir(execLine)
		kpfile := filepath.Join(execPath, "fh.fhk")
		fi, err := os.Stat(kpfile)
		if err == nil {
			if fi.IsDir() {
				log.Println(kpfile, "is a folder!")
				return "", false, errors.New("Key File Error")
			} else {
				return kpfile, true, nil
			}
		} else {
			return kpfile, false, nil
		}
	} else {
		fi, err := os.Stat(fname)
		if err == nil {
			if fi.IsDir() {
				log.Println(fname, "fname a folder!")
				return "", false, errors.New("Key File Error")
			} else {
				return fname, true, nil
			}
		} else {
			return fname, false, nil
		}
	}
}

func askSomething(caption string, retryOnEmpty bool) *string {
	hesaid := ""
	for {
		fmt.Printf(caption)
		fmt.Scanln(&hesaid)
		if len(hesaid) == 0 && !retryOnEmpty {
			continue
		}
		return &hesaid
	}
}
