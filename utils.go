// fh project utils.go
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
)

func destroy(fname string) error {
	_, err := os.Stat(fname)
	if err != nil {
		if *verbose {
			log.Println(fname, "does not exist")
		}
		return nil
	}
	err = shred(fname)
	if err != nil {
		return err
	}
	err = os.Truncate(fname, 0)
	if err != nil {
		return err
	}
	err = os.Remove(fname)
	if err != nil {
		return err
	}
	return nil
}

func shred(fname string) error {
	fi, err := os.Stat(fname)
	if err != nil {
		return err
	}
	sz := fi.Size()

	f, err := os.OpenFile(fname, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = overwrite(f, bytes.Repeat([]byte{0}, 65536), sz)
	if err != nil {
		return err
	}
	for i := 0; i < 7; i++ {
		err = overwrite(f, nil, sz)
		if err != nil {
			return err
		}
	}
	err = overwrite(f, bytes.Repeat([]byte{255}, 65536), sz)
	if err != nil {
		return err
	}
	defer f.Close()

	return nil
}

func overwrite(fo *os.File, what []byte, sz int64) error {
	if what == nil {
		what = make([]byte, 65536)
		_, err := io.ReadFull(rand.Reader, what)
		if err != nil {
			return err
		}
	}
	_, err := fo.Seek(0, 0)
	if err != nil {
		return err
	}
	for {
		sz -= 65536
		if sz >= 0 {
			_, err := fo.Write(what)
			if err != nil {
				return err
			}
		} else {
			_, err := fo.Write(what[:sz+65536])
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// canBePrepended check if a file can be 'prepended' to ours
// it can be if it starts with "BM" and the declared length (bytes 3-6)
// correspond to file length.
// this is due to the method used to strip it out when decrypting
func canBePrepended(toprepend string) error {
	// 'stat' it
	fi, err := os.Stat(toprepend)
	if err != nil {
		return err
	}
	// must be a regular file
	if !fi.Mode().IsRegular() {
		return errors.New("Not a file")
	}
	exf, err := os.Open(toprepend)
	// error opening? no good
	if err != nil {
		return err
	}
	// remember closing
	defer exf.Close()
	// read first 6 bytes ('BM'+4 bytes size)
	buf := make([]byte, 6)
	_, err = exf.Read(buf)
	// error reading? no good
	if err != nil {
		return err
	}
	// not a BMP-like file?
	if string(buf[:2]) != "BM" {
		return errors.New("Not a BMP")
	}
	putLenHere := binary.LittleEndian.Uint32(buf[2:6])
	if putLenHere != uint32(fi.Size()) {
		return errors.New(fmt.Sprintf("BMP size not matching file's size (%d/%d)", putLenHere, uint32(fi.Size())))
	}
	return nil
}

// prepend prepends a file to another
// before is the file to prepend
// payload is the file to be prepended
// final is the final file to obtain
func prepend(before string, payload string, final string) error {
	bf, err := os.Open(before)
	if err != nil {
		return err
	}
	defer bf.Close()
	pf, err := os.Open(payload)
	if err != nil {
		return err
	}
	defer pf.Close()
	ff, err := os.Create(final)
	if err != nil {
		return err
	}
	defer ff.Close()
	n, err := io.Copy(ff, bf)
	if err != nil {
		return err
	}
	log.Println(n, "bytes copied to", final)
	n, err = io.Copy(ff, pf)
	if err != nil {
		return err
	}
	log.Println(n, "bytes copied to", final)
	return nil
}

func canBeBlended(source string, container string) (*bmpHeader, *dibHeader, error) {
	sfi, err := os.Stat(source)
	if err != nil {
		return nil, nil, err
	}
	containerf, err := os.Open(container)
	if err != nil {
		return nil, nil, err
	}
	defer containerf.Close()
	bh, err := readBmpHeader(containerf)
	if err != nil {
		return nil, nil, err
	}
	log.Println(bh.printMe())
	if bh.marker != "BM" {
		return nil, nil, errors.New("Not BM file")
	}
	dh, err := readDibHeader(containerf)
	if err != nil {
		return nil, nil, err
	}
	log.Println(dh.printMe())
	if dh.typeLen != 40 {
		return nil, nil, errors.New("Not DIB sub-header")
	}
	if dh.compre != 0 {
		return nil, nil, errors.New("Compressed")
	}
	if dh.height*dh.width*3 < uint32(sfi.Size())*4 {
		return nil, nil, errors.New("Host file too short")
	}
	if dh.bitspp != 24 {
		return nil, nil, errors.New("BM file BPP is wrong")
	}
	if bh.offset != 54 {
		return nil, nil, errors.New("Color table present")
	}
	bh.r1r2 = uint32(sfi.Size())
	dh.marker = "MX"
	return bh, dh, nil
}

// blend blend a file into a BMP
// source is the file to hide
// container is the original 24bpp BMP
// mix is the resulting output file
func blend(source string, container string, mix string, debug bool) error {
	log.Println("Mixing", source, "and", container, "into", mix)
	sourcef, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourcef.Close()
	bh, dh, err := canBeBlended(source, container)
	if err != nil {
		return err
	}
	containerf, err := os.Open(container)
	if err != nil {
		return err
	}
	defer containerf.Close()
	// skip the 54 bytes headers
	n, err := containerf.Seek(54, 0)
	if err != nil || n != 54 {
		return errors.New("Cannot seek correctly")
	}

	rowLenInBits := dh.width * uint32(dh.bitspp)
	if rowLenInBits%32 != 0 {
		rowLenInBits = rowLenInBits + (32 - rowLenInBits%32)
	}
	rowLenInBytes := rowLenInBits / 8

	mixf, err := os.Create(mix)
	if err != nil {
		return err
	}
	defer mixf.Close()
	_, err = mixf.Write(bh.byteMe())
	if err != nil {
		return err
	}
	_, err = mixf.Write(dh.byteMe())
	if err != nil {
		return err
	}
	//_, err = mixf.Write(middle)
	//if err != nil {
	//	return err
	//}
	row := make([]byte, rowLenInBytes)
	brow := make([]byte, rowLenInBytes/4)
	for i := uint32(0); i < dh.height; i++ {
		n, err := containerf.Read(row)
		if err != nil {
			return err
		}
		if n != int(rowLenInBytes) {
			return errors.New("Error reading source row")
		}
		bn, berr := sourcef.Read(brow)
		if berr != nil && berr != io.EOF {
			return berr
		}
		for bi := 0; bi < bn; bi++ {
			diffuse := brow[bi]
			if bi == 0 && i == 0 && debug {
				log.Printf("Diffusing %02X in [%02X%02X%02X%02X]", diffuse, row[bi*4+0], row[bi*4+1], row[bi*4+2], row[bi*4+3])
			}
			for b := 0; b <= 3; b++ {
				row[bi*4+b] &= 0XFC
				row[bi*4+b] |= diffuse & 3
				//log.Printf("Diffusing bits %02X", (diffuse & 3))
				diffuse = diffuse >> 2
			}
			if bi == 0 && i == 0 && debug {
				log.Printf("Diffused %02X in  [%02X%02X%02X%02X]", brow[bi], row[bi*4+0], row[bi*4+1], row[bi*4+2], row[bi*4+3])
			}
		}
		_, err = mixf.Write(row)
		if err != nil {
			return err
		}
	}
	return nil
}

func isPrepended(source string) (bool, error) {
	sf, err := os.Open(source)
	if err != nil {
		return false, err
	}
	defer sf.Close()
	bh, err := readBmpHeader(sf)
	if err != nil {
		return false, nil
	}
	if bh.marker != "BM" {
		return false, nil
	}
	fi, err := sf.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() > int64(bh.bmpSize)+64 {
		return true, nil
	}
	return false, nil
}

func detach(source string, separated string) error {
	sf, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sf.Close()
	bh, err := readBmpHeader(sf)
	if err != nil {
		return err
	}
	if bh.marker != "BM" {
		return errors.New("Not a prependable file")
	}
	fi, err := sf.Stat()
	if err != nil {
		return err
	}
	if fi.Size() <= int64(bh.bmpSize)+64 {
		return errors.New("Nothing to separate")
	}
	separatedf, err := os.Create(separated)
	if err != nil {
		return err
	}
	defer separatedf.Close()
	_, err = sf.Seek(int64(bh.bmpSize), 0)
	if err != nil {
		return err
	}
	n, err := io.Copy(separatedf, sf)
	if err != nil {
		return err
	}
	log.Println("Detaching", separated, "from", source, ":", n, "bytes separated")
	return nil
}

func isBlended(source string) (bool, error) {
	sf, err := os.Open(source)
	if err != nil {
		return false, err
	}
	defer sf.Close()
	bh, err := readBmpHeader(sf)
	if err != nil {
		return false, nil
	}
	if bh.marker != "BM" {
		return false, nil
	}
	if bh.offset != 54 {
		return false, nil
	}
	dh, err := readDibHeader(sf)
	if err != nil {
		return false, nil
	}
	if dh.typeLen != 40 {
		return false, nil
	}
	if dh.bitspp != 24 {
		return false, nil
	}
	if dh.compre != 0 {
		return false, nil
	}
	if dh.marker != "MX" {
		return false, nil
	}
	return true, nil
}

func sblend(source string, extracted string) error {
	log.Println("Extracting", extracted, "from", source)
	sourcef, err := os.Open(source)
	if err != nil {
		return err
	}
	defer sourcef.Close()
	bh, err := readBmpHeader(sourcef)
	if err != nil {
		return err
	}
	log.Println(bh.printMe())
	if bh.marker != "BM" {
		return errors.New("Not BM file")
	}
	dh, err := readDibHeader(sourcef)
	if err != nil {
		return err
	}
	log.Println(dh.printMe())
	if dh.typeLen != 40 {
		return errors.New("Not DIB sub-header")
	}
	if dh.compre != 0 {
		return errors.New("Compressed")
	}
	if dh.bitspp != 24 {
		return errors.New("BM file BPP is wrong")
	}
	if dh.marker != "MX" {
		return errors.New("Not an MX DIB header")
	}
	rowLenInBits := dh.width * uint32(dh.bitspp)
	if rowLenInBits%32 != 0 {
		rowLenInBits = rowLenInBits + (32 - rowLenInBits%32)
	}
	rowLenInBytes := rowLenInBits / 8

	if bh.offset != 54 {
		return errors.New("Color table present")
	}
	embeddedResidual := bh.r1r2
	log.Println("Bytes to extract :", embeddedResidual)

	extractedf, err := os.Create(extracted)
	if err != nil {
		return err
	}
	defer extractedf.Close()
	row := make([]byte, rowLenInBytes)
	srow := make([]byte, rowLenInBytes/4)
	for {
		n, err := sourcef.Read(row)
		if err != nil {
			return err
		}
		if n != int(rowLenInBytes) {
			return errors.New("Error reading source row")
		}
		for bi := 0; bi < n; bi += 4 {
			srow[bi/4] = 0x00
			for b := 3; b >= 0; b-- {
				srow[bi/4] = srow[bi/4] << 2
				srow[bi/4] |= (row[bi+b] & 0x03)
			}
			//log.Printf("Recovering %02X", srow[bi/4])
		}
		if embeddedResidual < rowLenInBytes/4 {
			_, err := extractedf.Write(srow[:embeddedResidual])
			if err != nil {
				return err
			}
		} else {
			_, err := extractedf.Write(srow)
			if err != nil {
				return err
			}
		}
		if embeddedResidual < rowLenInBytes/4 {
			break
		}
		embeddedResidual -= (rowLenInBytes / 4)
		//log.Println("Bytes residual :", embeddedResidual)
	}
	return nil
}

func checkAndDelete(fileName string) error {
	fi, err := os.Stat(fileName)
	if err == nil {
		if fi.Mode().IsRegular() {
			// delete it
			return os.Remove(fileName)
		} else {
			return errors.New("output file exists and is not a regular file")
		}
	}
	// err != nil
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func prependOrBlendOrRename(inputName string, tryToPrepend string, tryToBlend string, finalName string) error {
	if len(tryToPrepend) == 0 && len(tryToBlend) == 0 {
		return os.Rename(inputName, finalName)
	}
	if len(tryToBlend) != 0 {
		// blend requested. Check if possibile
		_, _, err := canBeBlended(inputName, tryToBlend)
		if err != nil {
			// problems (not a BMP, size constraint, type of BMP, etc...)
			// print and simulate preprending with the same file
			log.Println("Blending in", tryToBlend, "is impossible:", err.Error())
			log.Println("Trying prepending")
			tryToPrepend = tryToBlend
		} else {
			// do it
			err := blend(inputName, tryToBlend, finalName, *verbose)
			if err != nil {
				// problems (SHOULD NOT HAPPEN HERE, CHECKED BEFORE!)
				// print and simulate prepending with the same file
				log.Println("Error blending in", tryToBlend, ":", err.Error())
				log.Println("Trying prepending")
				tryToPrepend = tryToBlend
			} else {
				// done
				return nil
			}
		}
	}
	if len(tryToPrepend) != 0 {
		err := canBePrepended(tryToPrepend)
		if err != nil {
			// cannot be done
			log.Println(tryToPrepend, "cannot be used as prepended file:", err.Error())
			// at tihs point, keep the file as is and just rename
			return os.Rename(inputName, finalName)
		} else {
			err := prepend(tryToPrepend, inputName, finalName)
			if err != nil {
				log.Println("Error prepending", tryToPrepend)
				// at tihs point, keep the file as is and just rename
				return os.Rename(inputName, finalName)
			} else {
				// done
				return nil
			}
		}
	}
	// should never come here
	return errors.New("Cannot manage!")
}
