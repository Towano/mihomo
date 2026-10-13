package juicity

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"

	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
)

// Version0 is juicity's protocol version byte; it replaces tuic's VER field in
// the CommandHead. Wire-compatible with daeuniverse/outbound protocol/juicity.
const Version0 byte = 0x0

// GenerateCertChainHash mirrors juicity's common.GenerateCertChainHash: the
// hash chain is SHA256 over each DER cert, then SHA256 over the running chain.
func GenerateCertChainHash(rawCerts [][]byte) (chainHash []byte) {
	for _, cert := range rawCerts {
		certHash := sha256.Sum256(cert)
		if chainHash == nil {
			chainHash = certHash[:]
		} else {
			newHash := sha256.Sum256(append(chainHash, certHash[:]...))
			chainHash = newHash[:]
		}
	}
	return chainHash
}

// Address is juicity's wire address (trojan-style metadata, not tuic v5's).
type Address struct {
	Typ  byte // 1=IPv4, 3=domain, 4=IPv6
	Addr []byte
	Port uint16
}

func NewAddress(metadata *C.Metadata) Address {
	switch metadata.AddrType() {
	case C.AtypIPv4:
		return Address{Typ: 1, Addr: metadata.DstIP.AsSlice(), Port: metadata.DstPort}
	case C.AtypIPv6:
		return Address{Typ: 4, Addr: metadata.DstIP.AsSlice(), Port: metadata.DstPort}
	default:
		host := metadata.Host
		addr := make([]byte, len(host)+1)
		addr[0] = byte(len(host))
		copy(addr[1:], host)
		return Address{Typ: 3, Addr: addr, Port: metadata.DstPort}
	}
}

func (a Address) Len() int {
	switch a.Typ {
	case 1:
		return 3 + 4
	case 4:
		return 3 + 16
	case 3:
		return 4 + len(a.Addr) - 1 // Addr already includes the leading len byte
	default:
		return 0
	}
}

// PackTo writes [type][addr][port] into dst, returning bytes written.
func (a Address) PackTo(dst []byte) int {
	dst[0] = a.Typ
	switch a.Typ {
	case 1:
		copy(dst[1:], a.Addr[:4])
		binary.BigEndian.PutUint16(dst[5:], a.Port)
		return 7
	case 4:
		copy(dst[1:], a.Addr[:16])
		binary.BigEndian.PutUint16(dst[17:], a.Port)
		return 19
	case 3:
		n := len(a.Addr) // includes len byte
		copy(dst[1:], a.Addr)
		binary.BigEndian.PutUint16(dst[1+n:], a.Port)
		return 1 + n + 2
	default:
		return 0
	}
}

// UnpackAddress reads a trojan-style address from r.
func UnpackAddress(r io.Reader) (addr Address, err error) {
	var head [1]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return
	}
	addr.Typ = head[0]
	var nb [2]byte
	switch addr.Typ {
	case 1:
		addr.Addr = make([]byte, 4)
		if _, err = io.ReadFull(r, addr.Addr); err != nil {
			return
		}
	case 4:
		addr.Addr = make([]byte, 16)
		if _, err = io.ReadFull(r, addr.Addr); err != nil {
			return
		}
	case 3:
		var lb [1]byte
		if _, err = io.ReadFull(r, lb[:]); err != nil {
			return
		}
		addr.Addr = make([]byte, int(lb[0])+1)
		addr.Addr[0] = lb[0]
		if _, err = io.ReadFull(r, addr.Addr[1:]); err != nil {
			return
		}
	default:
		err = fmt.Errorf("juicity: unexpected address type %d", addr.Typ)
		return
	}
	if _, err = io.ReadFull(r, nb[:]); err != nil {
		return
	}
	addr.Port = binary.BigEndian.Uint16(nb[:])
	return
}

func (a Address) Host() string {
	switch a.Typ {
	case 3:
		return string(a.Addr[1:])
	case 1, 4:
		ip, ok := netip.AddrFromSlice(a.Addr)
		if !ok {
			return ""
		}
		return ip.String()
	default:
		return ""
	}
}

func (a Address) AddrPort() (netip.AddrPort, error) {
	switch a.Typ {
	case 1, 4:
		ip, ok := netip.AddrFromSlice(a.Addr)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("juicity: bad ip addr")
		}
		return netip.AddrPortFrom(ip, a.Port), nil
	case 3:
		ip, err := net.ResolveIPAddr("ip", a.Host())
		if err != nil {
			return netip.AddrPort{}, err
		}
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("juicity: cannot resolve %s", a.Host())
		}
		return netip.AddrPortFrom(addr, a.Port), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("juicity: bad address type %d", a.Typ)
	}
}

// Authenticate is the juicity auth frame on a unidirectional stream:
// [VER=0][type=0][UUID 16B][TOKEN 32B]. Same layout as tuic v5 but VER=0.
func WriteAuthenticate(w io.Writer, uuid [16]byte, token [32]byte) error {
	buf := pool.Get(2 + 16 + 32)
	defer pool.Put(buf)
	buf[0] = Version0
	buf[1] = 0x0 // AuthenticateType
	copy(buf[2:], uuid[:])
	copy(buf[18:], token[:])
	_, err := w.Write(buf)
	return err
}

// Network byte used in the stream request header (trojan style, NOT tuic's
// CommandHead). tcp=1, udp=3.
func NetworkToByte(network string) byte {
	switch network {
	case "tcp":
		return 1
	case "udp":
		return 3
	default:
		return 0
	}
}
