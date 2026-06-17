package dnstest

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type Responder func(*dns.Msg) *dns.Msg

type Server struct {
	udpServer *dns.Server
	tcpServer *dns.Server
	udpConn   net.PacketConn
	tcpLn     net.Listener
}

func StartAuthoritativeServer(handler Responder) (*Server, error) {
	if handler == nil {
		return nil, fmt.Errorf("dnstest: responder is required")
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("dnstest: listen udp: %w", err)
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("dnstest: listen tcp: %w", err)
	}

	server := &Server{
		udpConn: udpConn,
		tcpLn:   tcpLn,
	}
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := handler(req)
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetRcode(req, dns.RcodeServerFailure)
		}
		if err := w.WriteMsg(resp); err != nil {
			_ = w.Close()
		}
	})

	server.udpServer = &dns.Server{PacketConn: udpConn, Handler: dnsHandler}
	server.tcpServer = &dns.Server{Listener: tcpLn, Handler: dnsHandler}

	go func() { _ = server.udpServer.ActivateAndServe() }()
	go func() { _ = server.tcpServer.ActivateAndServe() }()

	if err := waitReady("udp", udpConn.LocalAddr().String()); err != nil {
		_ = server.Close()
		return nil, err
	}
	if err := waitReady("tcp", tcpLn.Addr().String()); err != nil {
		_ = server.Close()
		return nil, err
	}
	return server, nil
}

func (s *Server) Close() error {
	var errs []string
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if s.udpServer != nil {
		if err := s.udpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.ShutdownContext(ctx); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if s.udpConn != nil {
		if err := s.udpConn.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			errs = append(errs, err.Error())
		}
	}
	if s.tcpLn != nil {
		if err := s.tcpLn.Close(); err != nil && !strings.Contains(err.Error(), "closed") {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("dnstest: close: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) UDPAddress() string {
	if s == nil || s.udpConn == nil {
		return ""
	}
	return s.udpConn.LocalAddr().String()
}

func (s *Server) TCPAddress() string {
	if s == nil || s.tcpLn == nil {
		return ""
	}
	return s.tcpLn.Addr().String()
}

func waitReady(network, address string) error {
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout(network, address, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("dnstest: %s listener %s did not become ready", network, address)
}
