// fh project headers.go
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type bmpHeader struct {
	marker  string
	bmpSize uint32
	r1r2    uint32
	offset  uint32
}

func (bh *bmpHeader) printMe() string {
	s := fmt.Sprintf("%s Len:%d (%d) +%d", bh.marker, bh.bmpSize, bh.r1r2, bh.offset)
	return s
}

func (bh *bmpHeader) byteMe() []byte {
	res := make([]byte, 14)
	res[0] = bh.marker[0]
	res[1] = bh.marker[1]
	binary.LittleEndian.PutUint32(res[2:6], bh.bmpSize)
	binary.LittleEndian.PutUint32(res[6:10], bh.r1r2)
	binary.LittleEndian.PutUint32(res[10:14], bh.offset)
	return res
}

func readBmpHeader(tf io.Reader) (*bmpHeader, error) {
	bh := new(bmpHeader)
	buf := make([]byte, 14)
	n, err := tf.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != 14 {
		return nil, errors.New(fmt.Sprintf("Not enough data:%d", n))
	}
	//fmt.Println(hex.EncodeToString(buf))
	bh.marker = string(buf[:2])

	bh.bmpSize = binary.LittleEndian.Uint32(buf[2:6])

	bh.r1r2 = binary.LittleEndian.Uint32(buf[6:10])

	bh.offset = binary.LittleEndian.Uint32(buf[10:])
	return bh, nil
}

type dibHeader struct {
	typeLen uint32
	width   uint32
	height  uint32
	planes  uint16
	bitspp  uint16
	compre  uint32
	rawsiz  uint32
	hrzres  uint32
	vrtres  uint32
	colors  uint32
	marker  string
	algo    byte
	blkpad  byte
}

func (dh *dibHeader) byteMe() []byte {
	res := make([]byte, 40)
	binary.LittleEndian.PutUint32(res[0:4], dh.typeLen)
	binary.LittleEndian.PutUint32(res[4:8], dh.width)
	binary.LittleEndian.PutUint32(res[8:12], dh.height)
	binary.LittleEndian.PutUint16(res[12:14], dh.planes)
	binary.LittleEndian.PutUint16(res[14:16], dh.bitspp)
	binary.LittleEndian.PutUint32(res[16:20], dh.compre)
	binary.LittleEndian.PutUint32(res[20:24], dh.rawsiz)
	binary.LittleEndian.PutUint32(res[24:28], dh.hrzres)
	binary.LittleEndian.PutUint32(res[28:32], dh.vrtres)
	binary.LittleEndian.PutUint32(res[32:36], dh.colors)
	res[36] = dh.marker[0]
	res[37] = dh.marker[1]
	res[38] = dh.algo
	res[39] = dh.blkpad
	return res
}

func (dh *dibHeader) printMe() string {
	s := fmt.Sprintf("T/L=%d,%d(w)x%d(h);%d col (%d/%d) size=%d res=%dx%dppm, col=%d,mark=%s(%d/%d)", dh.typeLen, dh.width, dh.height, dh.bitspp, dh.planes, dh.compre, dh.rawsiz, dh.hrzres, dh.vrtres, dh.colors, dh.marker, dh.algo, dh.blkpad)
	return s
}

func readDibHeader(tf io.Reader) (*dibHeader, error) {
	dh := new(dibHeader)

	buf := make([]byte, 40)
	n, err := tf.Read(buf[:4])
	if err != nil {
		return nil, err
	}
	if n != 4 {
		return nil, errors.New(fmt.Sprintf("Not enough data:%d", n))
	}

	dh.typeLen = binary.LittleEndian.Uint32(buf[:4])

	if dh.typeLen != 40 {
		return nil, errors.New(fmt.Sprintf("Wrong format:%d", n))
	}

	n, err = tf.Read(buf[4:])
	if err != nil {
		return nil, err
	}
	if n != 36 {
		return nil, errors.New(fmt.Sprintf("Not enough data:%d", n))
	}
	//fmt.Println(hex.EncodeToString(buf))
	dh.width = binary.LittleEndian.Uint32(buf[4:8])
	dh.height = binary.LittleEndian.Uint32(buf[8:12])
	dh.planes = binary.LittleEndian.Uint16(buf[12:14])
	dh.bitspp = binary.LittleEndian.Uint16(buf[14:16])
	dh.compre = binary.LittleEndian.Uint32(buf[16:20])
	dh.rawsiz = binary.LittleEndian.Uint32(buf[20:24])
	dh.hrzres = binary.LittleEndian.Uint32(buf[24:28])
	dh.vrtres = binary.LittleEndian.Uint32(buf[28:32])
	dh.colors = binary.LittleEndian.Uint32(buf[32:36])
	dh.marker = string(buf[36:38])
	dh.algo = buf[38]
	dh.blkpad = buf[39]

	return dh, nil
}
