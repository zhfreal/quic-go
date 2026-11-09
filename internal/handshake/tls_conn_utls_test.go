package handshake

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/apernet/quic-go/quicvarint"
	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

func TestUTLSConfigFromStd_Basic(t *testing.T) {
	pool := x509.NewCertPool()
	stdConf := &tls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		RootCAs:            pool,
	}

	uConf, err := utlsConfigFromStd(stdConf)
	require.NoError(t, err)
	require.NotNil(t, uConf)
	require.Equal(t, "example.com", uConf.ServerName)
	require.True(t, uConf.InsecureSkipVerify)
	require.Equal(t, []string{"h3"}, uConf.NextProtos)
	require.Equal(t, uint16(utls.VersionTLS13), uConf.MinVersion)
	require.Equal(t, uint16(utls.VersionTLS13), uConf.MaxVersion)
	require.True(t, uConf.SessionTicketsDisabled)
}

func TestUTLSConfigFromStd_Nil(t *testing.T) {
	uConf, err := utlsConfigFromStd(nil)
	require.NoError(t, err)
	require.NotNil(t, uConf)
	require.Equal(t, uint16(utls.VersionTLS13), uConf.MinVersion)
}

func TestUTLSConfigFromStd_UnsupportedFields(t *testing.T) {
	t.Run("VerifyConnection", func(t *testing.T) {
		conf := &tls.Config{
			VerifyConnection: func(tls.ConnectionState) error { return nil },
		}
		_, err := utlsConfigFromStd(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "VerifyConnection is not supported")
	})

	t.Run("ServerCertificates", func(t *testing.T) {
		conf := &tls.Config{
			Certificates: []tls.Certificate{{}},
		}
		_, err := utlsConfigFromStd(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server-side tls.Config fields are not supported")
	})

	t.Run("GetCertificate", func(t *testing.T) {
		conf := &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil },
		}
		_, err := utlsConfigFromStd(conf)
		require.Error(t, err)
		require.Contains(t, err.Error(), "server-side tls.Config fields are not supported")
	})
}

func TestUTLSConfigFromStd_ClientCert(t *testing.T) {
	called := false
	stdConf := &tls.Config{
		GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			called = true
			return &tls.Certificate{Certificate: [][]byte{{0x01}}}, nil
		},
	}

	uConf, err := utlsConfigFromStd(stdConf)
	require.NoError(t, err)
	require.NotNil(t, uConf.GetClientCertificate)

	cert, err := uConf.GetClientCertificate(&utls.CertificateRequestInfo{})
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, [][]byte{{0x01}}, cert.Certificate)
}

func TestSplitTransportParameters(t *testing.T) {
	var raw []byte
	raw = quicvarint.Append(raw, 0x01) // param id
	raw = quicvarint.Append(raw, 4)    // length
	raw = append(raw, 0x11, 0x22, 0x33, 0x44)

	raw = quicvarint.Append(raw, 0x04) // param id
	raw = quicvarint.Append(raw, 2)    // length
	raw = append(raw, 0xaa, 0xbb)

	tps, err := splitTransportParameters(raw)
	require.NoError(t, err)
	require.Len(t, tps, 2)
	require.Equal(t, uint64(0x01), tps[0].ID())
	require.Equal(t, []byte{0x11, 0x22, 0x33, 0x44}, tps[0].Value())
	require.Equal(t, uint64(0x04), tps[1].ID())
	require.Equal(t, []byte{0xaa, 0xbb}, tps[1].Value())

	// Roundtrip check: tps.Marshal() must match raw exactly
	marshaled := tps.Marshal()
	require.Equal(t, raw, marshaled)

	// Malformed truncated buffer
	_, err = splitTransportParameters([]byte{0x01})
	require.Error(t, err)

	_, err = splitTransportParameters([]byte{0x01, 0x05, 0xaa})
	require.Error(t, err)
}

func TestUTLSQUICConn_CloseNilSafety(t *testing.T) {
	var nilConn *utlsQUICConn
	require.NoError(t, nilConn.Close())

	emptyConn := &utlsQUICConn{}
	require.NoError(t, emptyConn.Close())
}

func TestUTLSQUICConn_LifecycleAndSetTransportParameters(t *testing.T) {
	stdConf := &tls.Config{
		ServerName:         "localhost",
		NextProtos:         []string{"h3"},
		InsecureSkipVerify: true,
	}

	conn, err := newUTLSQUICClient(stdConf)
	require.NoError(t, err)
	require.NotNil(t, conn)

	var rawParams []byte
	rawParams = quicvarint.Append(rawParams, 0x01)
	rawParams = quicvarint.Append(rawParams, 4)
	rawParams = append(rawParams, 0x00, 0x01, 0x02, 0x03)

	conn.SetTransportParameters(rawParams)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = conn.Start(ctx)
	require.NoError(t, err)

	// NextEvent should return WriteData for Initial ClientHello
	ev := conn.NextEvent()
	require.Equal(t, tls.QUICWriteData, ev.Kind)
	require.NotEmpty(t, ev.Data)

	// Close cleanly: when closing an in-progress handshake, close notify error is returned
	err = conn.Close()
	if err != nil {
		require.Contains(t, err.Error(), "close notify")
	}
}

func TestUTLSQUICConn_NextEvent_ErrorEventMapping(t *testing.T) {
	testErr := errors.New("simulated handshake failure")
	ev := newQUICErrorEvent(testErr)
	require.Equal(t, quicErrorEvent, ev.Kind)
	if quicErrorEvent != -1 {
		require.Equal(t, testErr, extractQUICEventError(ev))
	}
}

func TestUTLSQUICConn_UnsupportedMethods(t *testing.T) {
	conn := &utlsQUICConn{}
	require.Error(t, conn.SendSessionTicket(tls.QUICSessionTicketOptions{}))
	require.Error(t, conn.StoreSession(&tls.SessionState{}))
}
