//go:build go1.26

package handshake

import "crypto/tls"

const quicErrorEvent tls.QUICEventKind = tls.QUICErrorEvent

func extractQUICEventError(ev tls.QUICEvent) error {
	return ev.Err
}

func newQUICErrorEvent(err error) tls.QUICEvent {
	return tls.QUICEvent{
		Kind: quicErrorEvent,
		Err:  err,
	}
}
