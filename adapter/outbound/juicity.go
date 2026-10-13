package outbound

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/juicity"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type Juicity struct {
	*Base
	option *JuicityOption
	client *juicity.PoolClient

	quicConfig *quic.Config
	tlsConfig  *tls.Config
	echConfig  *ech.Config
}

type JuicityOption struct {
	BasicOption
	Name                 string   `proxy:"name"`
	Server               string   `proxy:"server"`
	Port                 int      `proxy:"port"`
	UUID                 string   `proxy:"uuid,omitempty"`
	Password             string   `proxy:"password,omitempty"`
	Ip                   string   `proxy:"ip,omitempty"`
	SNI                  string   `proxy:"sni,omitempty"`
	ALPN                 []string `proxy:"alpn,omitempty"`
	SkipCertVerify       bool     `proxy:"skip-cert-verify,omitempty"`
	PinnedPeerCertSha256 string   `proxy:"pinned-peer-cert-sha256,omitempty"`
	HeartbeatInterval    int      `proxy:"heartbeat-interval,omitempty"`
	ReduceRtt            bool     `proxy:"reduce-rtt,omitempty"`
	FastOpen             bool     `proxy:"fast-open,omitempty"`
	CongestionController string   `proxy:"congestion-controller,omitempty"`
	CWND                 int      `proxy:"cwnd,omitempty"`
	DisableMTUDiscovery  bool     `proxy:"disable-mtu-discovery,omitempty"`
	MaxOpenStreams       int      `proxy:"max-open-streams,omitempty"`
	Fingerprint          string   `proxy:"fingerprint,omitempty"`
	Certificate          string   `proxy:"certificate,omitempty"`
	PrivateKey           string   `proxy:"private-key,omitempty"`
	ECHOpts              ECHOptions `proxy:"ech-opts,omitempty"`
	ReceiveWindowConn    int      `proxy:"recv-window-conn,omitempty"`
	ReceiveWindow        int      `proxy:"recv-window,omitempty"`
}

// DialContext implements C.ProxyAdapter
func (j *Juicity) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := j.client.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, j), err
}

// ListenPacketContext implements C.ProxyAdapter
func (j *Juicity) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if err = j.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := j.client.ListenPacket(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return NewPacketConn(pc, j), nil
}

func (j *Juicity) dial(ctx context.Context) (pc net.PacketConn, quicConn *quic.Conn, err error) {
	pc, quicConn, err = common.DialQuic(ctx, j.addr, j.DialOptions(), j.dialer, j.tlsConfig, j.quicConfig, common.DialQuicOption{Early: j.option.ReduceRtt})
	if err != nil {
		return nil, nil, err
	}
	common.SetCongestionController(quicConn, j.option.CongestionController, j.option.CWND, "")
	return pc, quicConn, nil
}

// ProxyInfo implements C.ProxyAdapter
func (j *Juicity) ProxyInfo() C.ProxyInfo {
	info := j.Base.ProxyInfo()
	info.DialerProxy = j.option.DialerProxy
	return info
}

// parsePinnedCertChainSha256 accepts hex or base64 (std or URL encoding) for
// the pinned-cert-chain-sha256 field, matching juicity client's CLI parsing.
func parsePinnedCertChainSha256(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if h, err := base64.URLEncoding.DecodeString(s); err == nil {
		return h, nil
	}
	if h, err := base64.StdEncoding.DecodeString(s); err == nil {
		return h, nil
	}
	return hex.DecodeString(s)
}

func NewJuicity(option JuicityOption) (*Juicity, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	serverName := option.Server
	if option.SNI != "" {
		serverName = option.SNI
	}

	tlsConfig, err := ca.GetTLSConfig(ca.Option{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: option.SkipCertVerify,
			MinVersion:         tls.VersionTLS13,
		},
		Fingerprint:  option.Fingerprint,
		Certificate:  option.Certificate,
		PrivateKey:   option.PrivateKey,
	})
	if err != nil {
		return nil, err
	}

	if option.ALPN != nil {
		tlsConfig.NextProtos = option.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	pinnedHash, err := parsePinnedCertChainSha256(option.PinnedPeerCertSha256)
	if err != nil {
		return nil, fmt.Errorf("juicity: bad pinned-peer-cert-sha256: %w", err)
	}
	if len(pinnedHash) > 0 {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			got := juicity.GenerateCertChainHash(rawCerts)
			if len(got) != len(pinnedHash) {
				return fmt.Errorf("juicity: pinned cert chain hash length mismatch")
			}
			for i := range got {
				if got[i] != pinnedHash[i] {
					return fmt.Errorf("juicity: pinned cert chain hash mismatch")
				}
			}
			return nil
		}
	}

	if option.HeartbeatInterval <= 0 {
		option.HeartbeatInterval = 10000
	}
	if option.MaxOpenStreams == 0 {
		option.MaxOpenStreams = juicity.DefaultMaxOpenStreams
	}
	if option.CWND == 0 {
		option.CWND = 10
	}

	quicMaxOpenStreams := int64(option.MaxOpenStreams)
	quicMaxOpenStreams = quicMaxOpenStreams + int64(math.Ceil(float64(quicMaxOpenStreams)/10.0))
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     uint64(option.ReceiveWindowConn),
		MaxStreamReceiveWindow:         uint64(option.ReceiveWindowConn),
		InitialConnectionReceiveWindow: uint64(option.ReceiveWindow),
		MaxConnectionReceiveWindow:     uint64(option.ReceiveWindow),
		MaxIncomingStreams:             quicMaxOpenStreams,
		MaxIncomingUniStreams:          quicMaxOpenStreams,
		KeepAlivePeriod:                time.Duration(option.HeartbeatInterval) * time.Millisecond,
		DisablePathMTUDiscovery:        option.DisableMTUDiscovery,
		HandshakeIdleTimeout:           8 * time.Second,
	}
	if option.ReceiveWindowConn == 0 {
		quicConfig.InitialStreamReceiveWindow = common.DefaultStreamReceiveWindow / 10
		quicConfig.MaxStreamReceiveWindow = common.DefaultStreamReceiveWindow
	}
	if option.ReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = common.DefaultConnectionReceiveWindow / 10
		quicConfig.MaxConnectionReceiveWindow = common.DefaultConnectionReceiveWindow
	}

	if len(option.Ip) > 0 {
		addr = net.JoinHostPort(option.Ip, strconv.Itoa(option.Port))
	}

	echConfig, err := option.ECHOpts.Parse()
	if err != nil {
		return nil, err
	}

	uuidBytes := uuid.FromStringOrNil(option.UUID)
	if uuidBytes == uuid.Nil {
		return nil, fmt.Errorf("juicity: invalid uuid %q", option.UUID)
	}

	clientMaxOpenStreams := int64(option.MaxOpenStreams)
	if clientMaxOpenStreams == juicity.DefaultMaxOpenStreams {
		clientMaxOpenStreams = clientMaxOpenStreams - int64(math.Ceil(float64(clientMaxOpenStreams)/10.0))
	}
	if clientMaxOpenStreams < 1 {
		clientMaxOpenStreams = 1
	}

	j := &Juicity{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.Juicity,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.FastOpen,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option:     &option,
		quicConfig: quicConfig,
		tlsConfig:  tlsConfig,
		echConfig:  echConfig,
	}
	j.dialer = option.NewDialer(j.DialOptions())
	j.client = juicity.NewPoolClient(&juicity.ClientOption{
		Uuid:           uuidBytes,
		Password:       option.Password,
		MaxOpenStreams: clientMaxOpenStreams,
	}, j.dial)
	return j, nil
}
