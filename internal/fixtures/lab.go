package fixtures

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

type Lab struct {
	mu        sync.Mutex
	state     int
	servers   []*http.Server
	listeners []net.Listener
	ports     map[string]int
	closers   []func()
}

func Start() (*Lab, error) {
	l := &Lab{ports: map[string]int{}}
	httpPorts := map[string]int{"samsung": 18001, "hikvision": 18002, "ambiguous": 18003, "changing": 18004}
	for _, name := range []string{"samsung", "hikvision", "ambiguous", "changing"} {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", httpPorts[name]))
		if err != nil {
			l.Close()
			return nil, err
		}
		srv := &http.Server{ReadHeaderTimeout: 2 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.serve(name, w, r) })}
		l.listeners = append(l.listeners, ln)
		l.servers = append(l.servers, srv)
		l.ports[name] = httpPorts[name]
		go srv.Serve(ln)
	}
	if err := l.startCisco(); err != nil {
		l.Close()
		return nil, err
	}
	if err := l.startTLS(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
func (l *Lab) startCisco() error {
	ln, err := net.Listen("tcp", "127.0.0.1:12022")
	if err != nil {
		return err
	}
	l.listeners = append(l.listeners, ln)
	l.ports["cisco"] = 12022
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("Cisco IOS Software, CortaSentry authorized fixture\r\n"))
			c.Close()
		}
	}()
	return nil
}
func (l *Lab) startTLS() error {
	ln, err := net.Listen("tcp", "127.0.0.1:18443")
	if err != nil {
		return err
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "CortaSentry TLS Appliance Fixture")
		fmt.Fprint(w, "<title>Generic TLS Appliance</title>")
	}))
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.Listener = ln
	ts.StartTLS()
	l.ports["tls_appliance"] = 18443
	l.closers = append(l.closers, ts.Close)
	return nil
}
func (l *Lab) serve(name string, w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	state := l.state
	l.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch name {
	case "samsung":
		w.Header().Set("Server", "Samsung SmartTV")
		fmt.Fprint(w, "<title>Samsung SmartTV</title><p>Fixture Tizen TV</p>")
	case "hikvision":
		w.Header().Set("Server", "App-webs/")
		fmt.Fprint(w, "<title>HIKVISION Network Camera</title>")
	case "ambiguous":
		fmt.Fprint(w, "<title>Smart Device Camera TV</title>")
	case "changing":
		if state == 0 {
			w.Header().Set("X-Fixture-State", "one")
			fmt.Fprint(w, "<title>Changing Appliance State One</title>")
		} else {
			w.Header().Set("X-Fixture-State", "two")
			fmt.Fprint(w, "<title>Changing Appliance State Two</title>")
		}
	}
}
func (l *Lab) Ports() map[string]int {
	out := map[string]int{}
	for k, v := range l.ports {
		out[k] = v
	}
	return out
}
func (l *Lab) SetState(v int) { l.mu.Lock(); l.state = v; l.mu.Unlock() }
func (l *Lab) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, s := range l.servers {
		_ = s.Shutdown(ctx)
	}
	for _, fn := range l.closers {
		fn()
	}
	for _, ln := range l.listeners {
		_ = ln.Close()
	}
}
func (l *Lab) JSON() []byte { b, _ := json.Marshal(l.Ports()); return b }

var _ = tls.VersionTLS13
