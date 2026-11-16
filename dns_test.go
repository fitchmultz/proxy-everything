package main

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func listenReusableUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	listen := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketError error
		err := raw.Control(func(fd uintptr) {
			socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		return errors.Join(err, socketError)
	}}
	packetConn, err := listen.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		t.Fatalf("unexpected packet listener type %T", packetConn)
	}
	return udpConn
}

func TestDNSProxyRetainsUpstreamResponses(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeServerFailure} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			resolver := listenReusableUDP(t)
			defer resolver.Close()
			if err := resolver.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			request := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			payload, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}
			response := new(dns.Msg).SetRcode(request, rcode)
			if rcode == dns.RcodeSuccess {
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 42),
				}}
			}
			expected, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			upstreamDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 512)
				_, address, err := resolver.ReadFrom(buffer)
				if err == nil {
					_, err = resolver.WriteTo(expected, address)
				}
				upstreamDone <- err
			}()
			config, err := newEgressConfiguration(80)
			if err != nil {
				t.Fatal(err)
			}
			proxy := &dnsProxy{config: config}
			proxy.handlePacket(t.Context(), client.LocalAddr().(*net.UDPAddr), resolver.LocalAddr().(*net.UDPAddr), payload)
			if err := <-upstreamDone; err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 512)
			n, _, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], expected) {
				t.Fatalf("upstream response changed: got %x, want %x", buffer[:n], expected)
			}
		})
	}
}

func TestIsSandboxInternalHost(t *testing.T) {
	for _, test := range []struct {
		qname string
		want  bool
	}{
		{"sandbox.internal", true},
		{"sandbox.internal.", true},
		{"backups.sandbox.internal.", true},
		{"BACKUPS.SANDBOX.INTERNAL.", true},
		{"notsandbox.internal.", false},
		{"sandbox.internal.example.com.", false},
		{"example.com.", false},
		{"", false},
	} {
		if got := isSandboxInternalHost(test.qname); got != test.want {
			t.Errorf("isSandboxInternalHost(%q) = %v, want %v", test.qname, got, test.want)
		}
	}
}

func TestDNSProxySandboxInternalSkipsUpstream(t *testing.T) {
	for _, test := range []struct {
		name     string
		patterns []string
	}{
		{"explicit pattern", []string{"backups.sandbox.internal"}},
		{"wildcard mapping", []string{"*"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			resolver := listenReusableUDP(t)
			defer resolver.Close()

			config, err := newEgressConfiguration(80)
			if err != nil {
				t.Fatal(err)
			}
			if err := config.SetDNSConfig(test.patterns); err != nil {
				t.Fatal(err)
			}

			request := new(dns.Msg).SetQuestion("backups.sandbox.internal.", dns.TypeA)
			payload, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}

			proxy := &dnsProxy{config: config}
			start := time.Now()
			proxy.handlePacket(t.Context(), client.LocalAddr().(*net.UDPAddr), resolver.LocalAddr().(*net.UDPAddr), payload)

			if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 512)
			n, _, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("sandbox.internal query received no fallback: %v", err)
			}
			if elapsed := time.Since(start); elapsed >= dnsUpstreamTimeout {
				t.Fatalf("sandbox.internal fallback waited for upstream timeout: elapsed=%v", elapsed)
			}

			response := new(dns.Msg)
			if err := response.Unpack(buffer[:n]); err != nil {
				t.Fatal(err)
			}
			if response.Id != request.Id || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("unexpected fallback: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || !answer.A.Equal(net.IPv4(11, 0, 0, 1)) {
				t.Fatalf("unexpected fallback address: %s", response)
			}

			if err := resolver.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			upstreamBuffer := make([]byte, 512)
			n, _, err = resolver.ReadFrom(upstreamBuffer)
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Fatalf("expected upstream socket to receive zero packets (timeout), got n=%d err=%v", n, err)
			}
		})
	}
}

func TestDNSProxyUnavailableResolver(t *testing.T) {
	for _, test := range []struct {
		name      string
		qname     string
		patterns  []string
		answer    bool
		blackhole bool
	}{
		{"intercepted hostname", "backups.sandbox.internal.", []string{"backups.sandbox.internal"}, true, false},
		{"wildcard mapping", "backups.sandbox.internal.", []string{"*"}, true, false},
		{"unmatched hostname", "backups.sandbox.internal.", []string{"another.internal"}, false, false},
		{"silent drop upstream", "api.example.com.", []string{"*"}, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()

			var resolverAddress *net.UDPAddr
			var upstreamReceived chan struct{}
			if test.blackhole {
				resolver := listenReusableUDP(t)
				resolverAddress = resolver.LocalAddr().(*net.UDPAddr)
				drainDone := make(chan struct{})
				upstreamReceived = make(chan struct{}, 1)
				go func() {
					defer close(drainDone)
					drain := make([]byte, 512)
					for {
						if _, _, err := resolver.ReadFrom(drain); err != nil {
							return
						}
						select {
						case upstreamReceived <- struct{}{}:
						default:
						}
					}
				}()
				defer func() {
					_ = resolver.Close()
					<-drainDone
				}()
			} else {
				resolver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				resolverAddress = resolver.LocalAddr().(*net.UDPAddr)
				if err := resolver.Close(); err != nil {
					t.Fatal(err)
				}
			}

			config, err := newEgressConfiguration(80)
			if err != nil {
				t.Fatal(err)
			}
			if err := config.SetDNSConfig(test.patterns); err != nil {
				t.Fatal(err)
			}
			request := new(dns.Msg).SetQuestion(test.qname, dns.TypeA)
			payload, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}
			proxy := &dnsProxy{config: config}
			start := time.Now()
			proxy.handlePacket(t.Context(), client.LocalAddr().(*net.UDPAddr), resolverAddress, payload)

			buffer := make([]byte, 512)
			if !test.answer {
				raw, err := client.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var n int
				var receiveError error
				if err := raw.Control(func(fd uintptr) {
					n, _, receiveError = syscall.Recvfrom(int(fd), buffer, syscall.MSG_DONTWAIT)
				}); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(receiveError, syscall.EAGAIN) {
					t.Fatalf("unmatched query received a reply: bytes=%d error=%v", n, receiveError)
				}
				return
			}
			if err := client.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			n, _, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("intercepted query received no fallback: %v", err)
			}
			if test.blackhole {
				if elapsed := time.Since(start); elapsed >= 3*time.Second {
					t.Fatalf("silent-drop fallback exceeded 3s budget: elapsed=%v", elapsed)
				}
				select {
				case <-upstreamReceived:
				case <-time.After(100 * time.Millisecond):
					t.Fatal("blackhole upstream socket did not receive the forwarded query")
				}
			}
			response := new(dns.Msg)
			if err := response.Unpack(buffer[:n]); err != nil {
				t.Fatal(err)
			}
			if response.Id != request.Id || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("unexpected fallback: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || !answer.A.Equal(net.IPv4(11, 0, 0, 1)) {
				t.Fatalf("unexpected fallback address: %s", response)
			}
		})
	}
}
