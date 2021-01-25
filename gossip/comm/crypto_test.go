/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"context"
	"fmt"
	"github.com/Hyperledger-TWGC/tjfoc-gm/gmtls/gmcredentials"
	"net"
	"sync"
	"testing"
	"time"

	tls "github.com/Hyperledger-TWGC/tjfoc-gm/gmtls"
	"github.com/hyperledger/fabric/gossip/util"
	proto "github.com/hyperledger/fabric/protos/gossip"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
)

type gossipTestServer struct {
	lock           sync.Mutex
	remoteCertHash []byte
	selfCertHash   []byte
	ll             net.Listener
	s              *grpc.Server
}

func init() {
	util.SetupTestLogging()
}

func createTestServer(t *testing.T, cert *tls.Certificate) (srv *gossipTestServer, ll net.Listener) {
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{*cert},
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: true,
	}
	s := grpc.NewServer(grpc.Creds(gmcredentials.NewTLS(tlsConf)))
	ll, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:0"))
	assert.NoError(t, err, "%v", err)

	srv = &gossipTestServer{s: s, ll: ll, selfCertHash: certHashFromRawCert(cert.Certificate[0])}
	proto.RegisterGossipServer(s, srv)
	go s.Serve(ll)
	return srv, ll
}

func (s *gossipTestServer) stop() {
	s.s.Stop()
	s.ll.Close()
}

func (s *gossipTestServer) GossipStream(stream proto.Gossip_GossipStreamServer) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.remoteCertHash = extractCertificateHashFromContext(stream.Context())
	return nil
}

func (s *gossipTestServer) getClientCertHash() []byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.remoteCertHash
}

func (s *gossipTestServer) Ping(context.Context, *proto.Empty) (*proto.Empty, error) {
	return &proto.Empty{}, nil
}

func TestCertificateExtraction(t *testing.T) {
	cert := GenerateCertificatesOrPanic()
	srv, ll := createTestServer(t, &cert)
	defer srv.stop()

	clientCert := GenerateCertificatesOrPanic()
	clientCertHash := certHashFromRawCert(clientCert.Certificate[0])
	ta := gmcredentials.NewTLS(&tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, ll.Addr().String(), grpc.WithTransportCredentials(ta), grpc.WithBlock())
	assert.NoError(t, err, "%v", err)

	cl := proto.NewGossipClient(conn)
	stream, err := cl.GossipStream(context.Background())
	assert.NoError(t, err, "%v", err)
	if err != nil {
		return
	}

	time.Sleep(time.Second)
	clientSideCertHash := extractCertificateHashFromContext(stream.Context())
	serverSideCertHash := srv.getClientCertHash()

	assert.NotNil(t, clientSideCertHash)
	assert.NotNil(t, serverSideCertHash)

	assert.Equal(t, 32, len(clientSideCertHash), "client side cert hash is %v", clientSideCertHash)
	assert.Equal(t, 32, len(serverSideCertHash), "server side cert hash is %v", serverSideCertHash)

	assert.Equal(t, clientSideCertHash, srv.selfCertHash, "Server self hash isn't equal to client side hash")
	assert.Equal(t, clientCertHash, srv.remoteCertHash, "Server side and client hash aren't equal")
}
