// Package netclip implements a protocol for synchronizing a text clipboard
// over the local network.
package netclip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const (
	KeySize          = aes.BlockSize
	maxSkew          = 30 * time.Second
	magicStr         = "CLIP"
	magicStart       = 0
	magicLen         = len(magicStr)
	magicEnd         = magicStart + magicLen
	hmacStart        = magicEnd
	hmacLen          = sha256.Size
	hmacEnd          = hmacStart + hmacLen
	ivStart          = hmacEnd
	ivLen            = aes.BlockSize
	ivEnd            = ivStart + ivLen
	timeStart        = ivEnd
	timeLen          = 8 // uint64
	timeEnd          = timeStart + timeLen
	lenStart         = timeEnd
	lenLen           = 2 // uint16
	lenEnd           = lenStart + lenLen
	textStart        = lenEnd
	payloadStart     = timeStart
	payloadBlockSize = aes.BlockSize
	minPktSize       = textStart
	maxPktSize       = 1 << 16
)

var addr = &net.UDPAddr{
	IP:   net.ParseIP("224.0.0.1"),
	Port: 2547,
}

type Peer struct {
	Key  []byte
	conn *net.UDPConn
}

// NewPeer creates a new peer with the given key.
func NewPeer(key []byte) *Peer {
	if len(key) != KeySize {
		panic("bad key size")
	}
	return &Peer{Key: key}
}

// Connect connects the peer to the network.
func (p *Peer) Connect() error {
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	p.conn = conn
	return nil
}

// Close disconnects the peer from the network.
func (p *Peer) Close() {
	if p.conn != nil {
		p.conn.Close()
	}
	return
}

// Recv receives the next message from the network.
func (p *Peer) Recv() (string, net.Addr, error) {
	if p.conn == nil {
		return "", nil, errors.New("peer not connected")
	}
	pkt := make([]byte, maxPktSize)
	n, addr, err := p.conn.ReadFrom(pkt)
	if err != nil {
		return "", nil, err
	}
	s, err := p.decode(pkt[:n])
	if err != nil {
		return "", addr, err
	}
	return s, addr, err
}

// Send sends a message to other peers in the network.
func (p *Peer) Send(s string) error {
	if p.conn == nil {
		return errors.New("peer not connected")
	}
	pkt, err := p.encode(s)
	if err != nil {
		return err
	}
	_, err = p.conn.WriteTo(pkt, addr)
	return err
}

func (p *Peer) encode(s string) (pkt []byte, err error) {

	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	payloadSize := pad(timeLen+lenLen+len(s), payloadBlockSize)
	pktSize := payloadStart + payloadSize
	if pktSize > maxPktSize {
		return nil, errors.New("packet would be too big")
	}

	pkt = make([]byte, pktSize)

	p.setTextAndLength(pkt, s)
	p.setTimestamp(pkt)
	p.setIv(pkt)
	p.encrypt(pkt)
	p.setHmac(pkt)
	p.setMagic(pkt)

	return pkt, nil
}

func (p *Peer) decode(pkt []byte) (s string, err error) {

	defer func() {
		if e := recover(); e != nil {
			err = e.(error)
		}
	}()

	p.checkSize(pkt)
	p.checkMagic(pkt)
	p.checkHmac(pkt)
	p.decrypt(pkt)
	p.checkTimestamp(pkt)
	p.checkLength(pkt)

	return p.getText(pkt), nil
}

func (p *Peer) hash(data []byte) []byte {
	mac := hmac.New(sha256.New, p.Key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (p *Peer) encrypt(pkt []byte) {
	iv := pkt[ivStart:ivEnd]
	plaintext := pkt[payloadStart:]
	block, err := aes.NewCipher(p.Key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(plaintext, plaintext)
}

func (p *Peer) decrypt(pkt []byte) {
	iv := pkt[ivStart:ivEnd]
	ciphertext := pkt[payloadStart:]
	block, err := aes.NewCipher(p.Key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
}

func (p *Peer) setMagic(pkt []byte) {
	copy(pkt[magicStart:magicEnd], magicStr)
}

func (p *Peer) setHmac(pkt []byte) {
	mac := p.hash(pkt[payloadStart:])
	copy(pkt[hmacStart:hmacEnd], mac)
}

func (p *Peer) setIv(pkt []byte) {
	rand.Read(pkt[ivStart:ivEnd])
}

func (p *Peer) setTimestamp(pkt []byte) {
	t := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(pkt[timeStart:timeEnd], t)
}

func (p *Peer) setTextAndLength(pkt []byte, s string) {
	copy(pkt[textStart:textStart+len(s)], s)
	binary.BigEndian.PutUint16(pkt[lenStart:lenEnd], uint16(len(s)))
}

func (p *Peer) checkSize(pkt []byte) {
	if len(pkt) < minPktSize {
		panic(errors.New("short packet"))
	}
}

func (p *Peer) checkMagic(pkt []byte) {
	if !bytes.Equal([]byte(magicStr), pkt[magicStart:magicEnd]) {
		panic(errors.New("bad magic"))
	}
}

func (p *Peer) checkHmac(pkt []byte) {
	pktHmac := pkt[hmacStart:hmacEnd]
	dataHmac := p.hash(pkt[payloadStart:])
	if !hmac.Equal(pktHmac, dataHmac) {
		panic(errors.New("bad hmac"))
	}
}

func (p *Peer) checkTimestamp(pkt []byte) {
	sec := int64(binary.BigEndian.Uint64(pkt[timeStart:timeEnd]))
	t := time.Unix(sec, 0)
	elapsed := time.Since(t)
	if elapsed > maxSkew {
		panic(errors.New("message from the past"))
	} else if elapsed < -maxSkew {
		panic(errors.New("message from the future"))
	}
}

func (p *Peer) checkLength(pkt []byte) {
	l := int(binary.BigEndian.Uint16(pkt[lenStart:lenEnd]))
	if l > len(pkt)-textStart {
		panic(errors.New("invalid length"))
	}
}

func (p *Peer) getText(pkt []byte) string {
	l := int(binary.BigEndian.Uint16(pkt[lenStart:lenEnd]))
	return string(pkt[textStart : textStart+l])
}

// pad returns x rounded to the least multiple of m greater than or equal to x.
func pad(x, m int) int {
	r := x % m
	if r > 0 {
		return x + (m - x%m)
	} else {
		return x
	}
}
