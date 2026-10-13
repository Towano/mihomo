package juicity

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/pool"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/tuic/types"
	v5 "github.com/metacubex/mihomo/transport/tuic/v5"

	list "github.com/bahlo/generic-list-go"
	"github.com/metacubex/quic-go"
)

const DefaultMaxOpenStreams = 100

// DialFunc is juicity's variant of types.DialFunc — it must return both the
// QUIC connection and the raw UDP socket it rides on so the underlay path
// (port-0 UDP assocs) can send non-QUIC datagrams on the same socket.
type DialFunc func(ctx context.Context) (pc net.PacketConn, quicConn *quic.Conn, err error)

// ClientOption mirrors the tunable surface of daeuniverse's juicity client.
type ClientOption struct {
	Uuid           [16]byte
	Password       string
	MaxOpenStreams int64
}

type clientImpl struct {
	*ClientOption
	dialFn DialFunc

	quicConn  *quic.Conn
	underConn net.PacketConn // the raw UDP socket QUIC rides on; shared with the underlay path
	connMutex sync.Mutex

	openStreams atomic.Int64
	closed      atomic.Bool

	lastVisited atomic.Value

	// underlayAuth: psk records sent on the auth uni-stream, one per port-0 UDP assoc.
	underlayAuth chan *UnderlayAuth
	authStream   *quic.SendStream
	authStreamMu sync.Mutex
}

func (t *clientImpl) OpenStreams() int64 { return t.openStreams.Load() }

func (t *clientImpl) LastVisited() time.Time {
	if v := t.lastVisited.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

func (t *clientImpl) SetLastVisited(ts time.Time) { t.lastVisited.Store(ts) }

func (t *clientImpl) getQuicConn(ctx context.Context) (*quic.Conn, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn != nil {
		return t.quicConn, nil
	}
	pc, quicConn, err := t.dialFn(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		_ = t.sendAuthentication(quicConn)
	}()
	t.underConn = pc
	t.quicConn = quicConn
	t.openStreams.Store(0)
	return quicConn, nil
}

// sendAuthentication opens a uni-stream, writes
// [VER=0][AuthenticateType=0][UUID][TOKEN], then keeps the stream open to
// relay UnderlayAuth records as port-0 UDP assocs are created.
func (t *clientImpl) sendAuthentication(quicConn *quic.Conn) (err error) {
	defer func() { t.deferQuicConn(quicConn, err) }()
	stream, err := quicConn.OpenUniStream()
	if err != nil {
		return err
	}
	token, err := v5.GenToken(quicConn.ConnectionState(), t.Uuid, t.Password)
	if err != nil {
		return err
	}
	if err = WriteAuthenticate(stream, t.Uuid, token); err != nil {
		return err
	}
	// stash the stream so the underlay path can send psk records on it.
	t.authStreamMu.Lock()
	t.authStream = stream
	t.authStreamMu.Unlock()

	// pump underlay-auth records for the life of the connection.
	for {
		select {
		case <-quicConn.Context().Done():
			return quicConn.Context().Err()
		case auth, ok := <-t.underlayAuth:
			if !ok {
				return nil
			}
			buf := pool.Get(auth.Len())
			n := auth.PackTo(buf)
			if _, werr := stream.Write(buf[:n]); werr != nil {
				pool.Put(buf)
				return werr
			}
			pool.Put(buf)
		}
	}
}

// DialAuth registers a port-0 UDP assoc by generating iv+psk and queuing them
// on the auth stream. Returns them so the caller can build the underlay conn.
func (t *clientImpl) DialAuth(ctx context.Context, metadata *C.Metadata) (iv, psk []byte, err error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}
	if _, err = t.getQuicConn(ctx); err != nil {
		return nil, nil, err
	}
	iv = pool.Get(underlaySaltLen)
	iv[0], iv[1] = 0, 0
	if _, err := rand.Read(iv[2:]); err != nil {
		pool.Put(iv)
		return nil, nil, err
	}
	psk = pool.Get(underlayKeyLen)
	if _, err := rand.Read(psk); err != nil {
		pool.Put(iv)
		pool.Put(psk)
		return nil, nil, err
	}
	auth := &UnderlayAuth{
		IV:   iv,
		Psk:  psk,
		Addr: NewAddress(metadata),
	}
	select {
	case t.underlayAuth <- auth:
		return iv, psk, nil
	case <-ctx.Done():
		pool.Put(iv)
		pool.Put(psk)
		return nil, nil, ctx.Err()
	}
}

func (t *clientImpl) deferQuicConn(quicConn *quic.Conn, err error) {
	var netError net.Error
	if err != nil && errors.As(err, &netError) {
		t.forceClose(quicConn, err)
	}
}

func (t *clientImpl) forceClose(quicConn *quic.Conn, err error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if quicConn == nil {
		quicConn = t.quicConn
	}
	if quicConn != nil {
		if quicConn == t.quicConn {
			t.quicConn = nil
		}
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		_ = quicConn.CloseWithError(v5.ProtocolError, errStr)
	}
}

func (t *clientImpl) Close() {
	t.closed.Store(true)
	if t.openStreams.Load() == 0 {
		t.forceClose(nil, types.ClientClosed)
	}
}

// DialContext: [network=1][trojan-addr] then payload.
func (t *clientImpl) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	quicConn, err := t.getQuicConn(ctx)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, types.TooManyOpenStreams
	}
	stream, err := func() (net.Conn, error) {
		defer func() {
			if err != nil {
				t.deferQuicConn(quicConn, err)
			}
		}()
		quicStream, err := quicConn.OpenStream()
		if err != nil {
			t.openStreams.Add(-1)
			return nil, err
		}
		addr := NewAddress(metadata)
		buf := pool.Get(1 + addr.Len())
		defer pool.Put(buf)
		buf[0] = NetworkToByte("tcp")
		addr.PackTo(buf[1:])
		if _, err = quicStream.Write(buf); err != nil {
			t.openStreams.Add(-1)
			_ = quicStream.Close()
			return nil, fmt.Errorf("juicity: write request header: %w", err)
		}
		return types.NewQuicStreamConn(
			quicStream,
			quicConn.LocalAddr(),
			quicConn.RemoteAddr(),
			func() {
				time.AfterFunc(C.DefaultTCPTimeout, func() {
					openStreams := t.openStreams.Add(-1)
					if openStreams == 0 && t.closed.Load() {
						t.forceClose(quicConn, types.ClientClosed)
					}
				})
			},
		), nil
	}()
	return stream, err
}

// ListenPacket routes UDP assocs two ways:
//   - target port 0: juicity's "underlay" path — raw UDP on the same socket,
//     chacha20-poly1305 framed, psk exchanged on the auth uni-stream.
//   - otherwise: one bidirectional QUIC stream per association with
//     [network=3][addr] then [addr][2B len][payload] framing.
func (t *clientImpl) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	if metadata.DstPort == 0 {
		return t.dialUnderlay(ctx, metadata)
	}
	quicConn, err := t.getQuicConn(ctx)
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	if openStreams >= t.MaxOpenStreams {
		t.openStreams.Add(-1)
		return nil, types.TooManyOpenStreams
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		t.openStreams.Add(-1)
		return nil, err
	}
	addr := NewAddress(metadata)
	header := pool.Get(1 + addr.Len())
	header[0] = NetworkToByte("udp")
	addr.PackTo(header[1:])
	if _, err = quicStream.Write(header); err != nil {
		pool.Put(header)
		t.openStreams.Add(-1)
		_ = quicStream.Close()
		return nil, fmt.Errorf("juicity: write udp assoc header: %w", err)
	}
	pool.Put(header)

	pc := &udpStreamPacketConn{
		stream:   quicStream,
		quicConn: quicConn,
		closeDeferFn: func() {
			time.AfterFunc(C.DefaultUDPTimeout, func() {
				openStreams := t.openStreams.Add(-1)
				if openStreams == 0 && t.closed.Load() {
					t.forceClose(quicConn, types.ClientClosed)
				}
			})
		},
	}
	return pc, nil
}

// dialUnderlay implements juicity's port-0 UDP path: negotiate a psk on the
// auth uni-stream, then wrap every datagram in chacha20-poly1305 and send it
// over the same UDP socket QUIC uses.
func (t *clientImpl) dialUnderlay(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	iv, psk, err := t.DialAuth(ctx, metadata)
	if err != nil {
		return nil, err
	}
	t.connMutex.Lock()
	underConn := t.underConn
	t.connMutex.Unlock()
	if underConn == nil {
		return nil, fmt.Errorf("juicity: no underlay socket for port-0 UDP")
	}
	proxyAddr, err := net.ResolveUDPAddr("udp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	tgtAddr, err := net.ResolveUDPAddr("udp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	openStreams := t.openStreams.Add(1)
	_ = openStreams // captured in closeDeferFn closure below
	pc := &underlayPacketConn{
		pc:        underConn,
		proxyAddr: proxyAddr,
		key:       &UnderlayKey{MasterKey: psk},
		firstIv:   iv,
		tgtAddr:   tgtAddr,
		closeDeferFn: func() {
			time.AfterFunc(C.DefaultUDPTimeout, func() {
				openStreams := t.openStreams.Add(-1)
				if openStreams == 0 && t.closed.Load() {
					t.forceClose(nil, types.ClientClosed)
				}
			})
		},
	}
	return pc, nil
}

// udpStreamPacketConn frames each UDP packet as
// [trojan-addr][uint16 len][payload] on a dedicated bidirectional stream.
type udpStreamPacketConn struct {
	stream       *quic.Stream
	quicConn     *quic.Conn
	closeDeferFn func()
	closeOnce    sync.Once
}

func (c *udpStreamPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	metadata := &C.Metadata{}
	if err := metadata.SetRemoteAddr(addr); err != nil {
		return 0, err
	}
	a := NewAddress(metadata)
	buf := pool.Get(a.Len() + 2 + len(b))
	defer pool.Put(buf)
	n := a.PackTo(buf)
	binary.BigEndian.PutUint16(buf[n:], uint16(len(b)))
	copy(buf[n+2:], b)
	if _, err := c.stream.Write(buf[:n+2+len(b)]); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *udpStreamPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	addr, err := UnpackAddress(c.stream)
	if err != nil {
		return 0, nil, err
	}
	var lb [2]byte
	if _, err = io.ReadFull(c.stream, lb[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint16(lb[:]))
	var n int
	if length <= len(b) {
		if n, err = io.ReadFull(c.stream, b[:length]); err != nil {
			return 0, nil, err
		}
	} else {
		if n, err = io.ReadFull(c.stream, b); err != nil {
			return 0, nil, err
		}
		_, _ = io.CopyN(io.Discard, c.stream, int64(length-len(b)))
	}
	ap, err := addr.AddrPort()
	if err != nil {
		return n, nil, nil
	}
	return n, net.UDPAddrFromAddrPort(ap), nil
}

func (c *udpStreamPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpStreamPacketConn) Write(b []byte) (int, error) {
	return 0, fmt.Errorf("juicity: Write on PacketConn needs WriteTo")
}

func (c *udpStreamPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.closeDeferFn != nil {
			defer c.closeDeferFn()
		}
		_ = c.stream.SetWriteDeadline(time.Now())
		c.stream.CancelRead(0)
		err = c.stream.Close()
	})
	return err
}

func (c *udpStreamPacketConn) LocalAddr() net.Addr                { return c.quicConn.LocalAddr() }
func (c *udpStreamPacketConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *udpStreamPacketConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *udpStreamPacketConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// Client wraps clientImpl with ref-counting so the pool can evict idle conns.
type Client interface {
	DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error)
	ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error)
	Close()
	OpenStreams() int64
	LastVisited() time.Time
	SetLastVisited(time.Time)
}

type client struct {
	*clientImpl
}

func (t *client) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	conn, err := t.clientImpl.DialContext(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *client) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	pc, err := t.clientImpl.ListenPacket(ctx, metadata)
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *client) forceClose() { t.clientImpl.forceClose(nil, types.ClientClosed) }

func NewClient(clientOption *ClientOption, dialFn DialFunc) Client {
	ci := &clientImpl{
		ClientOption: clientOption,
		dialFn:       dialFn,
		underlayAuth: make(chan *UnderlayAuth, 64),
	}
	c := &client{ci}
	runtime.SetFinalizer(c, closeClient)
	log.Debugln("New Juicity Client at %p", c)
	return c
}

func closeClient(c *client) {
	log.Debugln("Close Juicity Client at %p", c)
	c.forceClose()
}

// PoolClient mirrors tuic.PoolClient: one clientImpl per QUIC connection,
// separate TCP/UDP pools so UDP assoc churn doesn't churn the TCP pool.
type PoolClient struct {
	newClientOption *ClientOption
	dialFn          DialFunc

	tcpClients      list.List[Client]
	tcpClientsMutex sync.Mutex
	udpClients      list.List[Client]
	udpClientsMutex sync.Mutex
}

func (t *PoolClient) DialContext(ctx context.Context, metadata *C.Metadata) (net.Conn, error) {
	conn, err := t.getClient(false).DialContext(ctx, metadata)
	if errors.Is(err, types.TooManyOpenStreams) {
		conn, err = t.newClient(false).DialContext(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefConn(conn, t), err
}

func (t *PoolClient) ListenPacket(ctx context.Context, metadata *C.Metadata) (net.PacketConn, error) {
	pc, err := t.getClient(true).ListenPacket(ctx, metadata)
	if errors.Is(err, types.TooManyOpenStreams) {
		pc, err = t.newClient(true).ListenPacket(ctx, metadata)
	}
	if err != nil {
		return nil, err
	}
	return N.NewRefPacketConn(pc, t), nil
}

func (t *PoolClient) newClient(udp bool) (c Client) {
	clients := &t.tcpClients
	mu := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		mu = &t.udpClientsMutex
	}
	mu.Lock()
	defer mu.Unlock()
	c = NewClient(t.newClientOption, t.dialFn)
	c.SetLastVisited(time.Now())
	clients.PushFront(c)
	return c
}

func (t *PoolClient) getClient(udp bool) Client {
	clients := &t.tcpClients
	mu := &t.tcpClientsMutex
	if udp {
		clients = &t.udpClients
		mu = &t.udpClientsMutex
	}
	var best Client
	mu.Lock()
	for it := clients.Front(); it != nil; {
		c := it.Value
		if c == nil {
			next := it.Next()
			clients.Remove(it)
			it = next
			continue
		}
		if best == nil || c.OpenStreams() < best.OpenStreams() {
			best = c
		}
		it = it.Next()
	}
	for it := clients.Front(); it != nil; {
		c := it.Value
		if c != best && c.OpenStreams() == 0 && time.Since(c.LastVisited()) > 30*time.Minute {
			c.Close()
			next := it.Next()
			clients.Remove(it)
			it = next
			continue
		}
		it = it.Next()
	}
	mu.Unlock()
	if best == nil {
		return t.newClient(udp)
	}
	best.SetLastVisited(time.Now())
	return best
}

func NewPoolClient(clientOption *ClientOption, dialFn DialFunc) *PoolClient {
	opt := *clientOption
	return &PoolClient{
		newClientOption: &opt,
		dialFn:          dialFn,
	}
}
