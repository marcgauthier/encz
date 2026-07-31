package sqliteseal

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

var errReplicationHeartbeatTimeout = errors.New("replication: peer heartbeat timeout")

type replicationLivenessConn struct {
	net.Conn
	timeout time.Duration
}

func newReplicationLivenessConn(connection net.Conn, timeout time.Duration) net.Conn {
	return &replicationLivenessConn{Conn: connection, timeout: timeout}
}

func (c *replicationLivenessConn) Read(buffer []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Read(buffer)
}

func (c *replicationLivenessConn) Write(buffer []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	return c.Conn.Write(buffer)
}

func configureReplicationTCPKeepalive(connection net.Conn, interval, timeout time.Duration) error {
	for {
		if tcp, ok := connection.(*net.TCPConn); ok {
			probeInterval := (timeout - interval) / 3
			if probeInterval < time.Second {
				probeInterval = time.Second
			}
			return tcp.SetKeepAliveConfig(net.KeepAliveConfig{
				Enable:   true,
				Idle:     interval,
				Interval: probeInterval,
				Count:    3,
			})
		}
		unwrapper, ok := connection.(interface{ NetConn() net.Conn })
		if !ok {
			return nil
		}
		next := unwrapper.NetConn()
		if next == nil || next == connection {
			return nil
		}
		connection = next
	}
}

func normalizeReplicationConnectionError(err error) error {
	if err == nil {
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return errReplicationHeartbeatTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return errors.New("replication: peer connection closed")
	}
	return err
}

func sanitizedReplicationConnectionError(err error) string {
	err = normalizeReplicationConnectionError(err)
	if err == nil {
		return ""
	}
	message := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	const maximumErrorBytes = 512
	if len(message) > maximumErrorBytes {
		message = message[:maximumErrorBytes]
	}
	return message
}
