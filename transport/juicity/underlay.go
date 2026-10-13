package juicity

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// JuicityReusedInfo is the HKDF info string used for the UDP underlay subkey.
// Matches daeuniverse/outbound ciphers.JuicityReusedInfo.
var JuicityReusedInfo = []byte("juicity-reused-info")

const (
	underlaySaltLen = 32
	underlayKeyLen  = 32
	underlayNonceLen = 12
	underlayTagLen  = 16
)

var underlayZeroNonce [underlayNonceLen]byte

// UnderlayKey wraps a session psk for chacha20-poly1305 underlay crypto.
type UnderlayKey struct {
	MasterKey []byte
}

// underlaySubKey derives the AEAD key via HKDF-SHA1(masterKey, salt,
// "juicity-reused-info") — same construction as dae's shadowsocks.Key.
func underlaySubKey(masterKey, salt []byte) ([]byte, error) {
	subKey := make([]byte, underlayKeyLen)
	kdf := hkdf.New(sha1.New, masterKey, salt, JuicityReusedInfo)
	if _, err := io.ReadFull(kdf, subKey); err != nil {
		return nil, err
	}
	return subKey, nil
}

// EncryptUnderlay writes [salt][tag||ciphertext] into dst.
// dst must be at least underlaySaltLen + len(b) + underlayTagLen.
func EncryptUnderlay(dst, b, salt, masterKey []byte) (int, error) {
	subKey, err := underlaySubKey(masterKey, salt)
	if err != nil {
		return 0, err
	}
	ciph, err := chacha20poly1305.New(subKey)
	if err != nil {
		return 0, err
	}
	copy(dst, salt)
	sealed := ciph.Seal(dst[underlaySaltLen:underlaySaltLen], underlayZeroNonce[:], b, nil)
	return underlaySaltLen + len(sealed), nil
}

// DecryptUnderlay reads [salt][tag||ciphertext] from src, writes plaintext into dst.
func DecryptUnderlay(dst, src, masterKey []byte) (int, error) {
	if len(src) < underlaySaltLen+underlayTagLen {
		return 0, fmt.Errorf("juicity: underlay packet too short")
	}
	salt := src[:underlaySaltLen]
	subKey, err := underlaySubKey(masterKey, salt)
	if err != nil {
		return 0, err
	}
	ciph, err := chacha20poly1305.New(subKey)
	if err != nil {
		return 0, err
	}
	opened, err := ciph.Open(dst[:0], underlayZeroNonce[:], src[underlaySaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(opened), nil
}

// UnderlayAuth is the auth record the client pushes on the auth uni-stream to
// declare a new UDP-underlay association: [iv][psk][trojan-metadata].
type UnderlayAuth struct {
	IV  []byte // underlaySaltLen; first two bytes must be 0
	Psk []byte // underlayKeyLen
	// Addr of the assoc target. In the reference impl this is a trojanc
	// Metadata; we keep a juicity Address for consistency.
	Addr Address
}

// PackTo serialises to [iv][psk][addr] (the addr is a stream request metadata
// without a leading network byte — the server reads it from the auth stream).
func (a *UnderlayAuth) PackTo(dst []byte) int {
	copy(dst, a.IV)
	copy(dst[len(a.IV):], a.Psk)
	n := len(a.IV) + len(a.Psk)
	return n + a.Addr.PackTo(dst[n:])
}

func (a *UnderlayAuth) Len() int {
	return len(a.IV) + len(a.Psk) + a.Addr.Len()
}

// underlayPacketConn speaks UDP to the proxy over the same UDP socket QUIC
// uses, wrapping every datagram in chacha20-poly1305 with a session-psk
// negotiated on the auth uni-stream. Only used when the target port is 0.
// NOTE: the socket is shared with the QUIC conn — reads on the raw socket see
// non-QUIC packets only because the QUIC transport filters them out first.
type underlayPacketConn struct {
	pc           net.PacketConn // raw UDP socket QUIC rides on
	proxyAddr    net.Addr       // proxy server's UDP addr
	key          *UnderlayKey
	firstIv      []byte
	tgtAddr      net.Addr // target for ReadFrom reply
	closeDeferFn func()
	mu           sync.Mutex
	closeOnce    sync.Once
}

func (c *underlayPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var salt []byte
	if c.firstIv != nil {
		salt = c.firstIv
		c.firstIv = nil
	} else {
		salt = pool.Get(underlaySaltLen)
		salt[0], salt[1] = 0, 0
		if _, err := rand.Read(salt[2:]); err != nil {
			pool.Put(salt)
			return 0, err
		}
		defer pool.Put(salt)
	}

	buf := pool.Get(underlaySaltLen + len(b) + underlayTagLen)
	defer pool.Put(buf)
	n, err := EncryptUnderlay(buf, b, salt, c.key.MasterKey)
	if err != nil {
		return 0, err
	}
	return c.pc.WriteTo(buf[:n], c.proxyAddr)
}

func (c *underlayPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := pool.Get(len(b) + underlaySaltLen + underlayTagLen)
	defer pool.Put(buf)
	n, _, err := c.pc.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	dec, err := DecryptUnderlay(b, buf[:n], c.key.MasterKey)
	if err != nil {
		return 0, nil, err
	}
	return dec, c.tgtAddr, nil
}

func (c *underlayPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *underlayPacketConn) Write(b []byte) (int, error) {
	return c.WriteTo(b, c.tgtAddr)
}

func (c *underlayPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.closeDeferFn != nil {
			defer c.closeDeferFn()
		}
		err = c.pc.Close()
	})
	return err
}

func (c *underlayPacketConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *underlayPacketConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *underlayPacketConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *underlayPacketConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }
