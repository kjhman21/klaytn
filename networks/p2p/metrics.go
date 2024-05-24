// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from p2p/metrics.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

// Contains the meters and timers used by the networking layer.

package p2p

import (
	"net"

	metricutils "github.com/klaytn/klaytn/metrics/utils"

	"github.com/rcrowley/go-metrics"
)

var (
	ingressConnectMeter = metrics.NewRegisteredMeter("p2p/InboundConnects", nil)
	ingressTrafficMeter = metrics.NewRegisteredMeter("p2p/InboundTraffic", nil)
	egressConnectMeter  = metrics.NewRegisteredMeter("p2p/OutboundConnects", nil)
	egressTrafficMeter  = metrics.NewRegisteredMeter("p2p/OutboundTraffic", nil)

	// The peer can be connected to one or more network ports.
	// Therefore, the connection state with the abstracted peer is measured by peerXXXCountGauge
	// and the connection at the network port level is measured by connectionXXXCountGauge.
	peerCountGauge    = metrics.NewRegisteredGauge("p2p/PeerCountGauge", nil)
	peerInCountGauge  = metrics.NewRegisteredGauge("p2p/PeerInCountGauge", nil)
	peerOutCountGauge = metrics.NewRegisteredGauge("p2p/PeerOutCountGauge", nil)

	connectionCountGauge    = metrics.NewRegisteredGauge("p2p/ConnectionCountGauge", nil)
	connectionInCountGauge  = metrics.NewRegisteredGauge("p2p/ConnectionInCountGauge", nil)
	connectionOutCountGauge = metrics.NewRegisteredGauge("p2p/ConnectionOutCountGauge", nil)

	dialTryCounter  = metrics.NewRegisteredCounter("p2p/DialTryCounter", nil)
	dialFailCounter = metrics.NewRegisteredCounter("p2p/DialFailCounter", nil)

	writeMsgTimeOutCounter = metrics.NewRegisteredCounter("p2p/WriteMsgTimeOutCounter", nil)
)

// meteredConn is a wrapper around a network TCP connection that meters both the
// inbound and outbound network traffic.
type meteredConn struct {
	*net.TCPConn // Network connection to wrap with metering
}

// newMeteredConn creates a new metered connection, also bumping the ingress or
// egress connection meter. If the metrics system is disabled, this function
// returns the original object.
func newMeteredConn(conn net.Conn, ingress bool) net.Conn {
	// Short circuit if metrics are disabled
	if !metricutils.Enabled {
		return conn
	}
	// Otherwise bump the connection counters and wrap the connection
	if ingress {
		ingressConnectMeter.Mark(1)
	} else {
		egressConnectMeter.Mark(1)
	}
	return &meteredConn{conn.(*net.TCPConn)}
}

// Read delegates a network read to the underlying connection, bumping the ingress
// traffic meter along the way.
func (c *meteredConn) Read(b []byte) (n int, err error) {
	n, err = c.TCPConn.Read(b)
	ingressTrafficMeter.Mark(int64(n))
	return
}

// Write delegates a network write to the underlying connection, bumping the
// egress traffic meter along the way.
func (c *meteredConn) Write(b []byte) (n int, err error) {
	n, err = c.TCPConn.Write(b)
	egressTrafficMeter.Mark(int64(n))
	return
}
