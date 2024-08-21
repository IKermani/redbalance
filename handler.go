// Package redbalance is a plugin for rewriting responses to do "load balancing"
package redbalance

import (
	"context"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// RedBalance RoundRobin is a plugin to rewrite responses for "load balancing".
type RedBalance struct {
	Next    plugin.Handler
	shuffle func(*dns.Msg) *dns.Msg
	redisDB *Redis
}

// ServeDNS implements the plugin.Handler interface.
func (lb RedBalance) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	// Use weightedRoundRobin to handle the request
	m := lb.shuffle(r)
	if m != nil {
		m.RecursionAvailable = true
		err := w.WriteMsg(m)
		if err != nil {
			return 0, err
		}
		return dns.RcodeSuccess, nil
	}

	// If no match, forward to the next plugin
	return plugin.NextOrFailure(lb.Name(), lb.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (lb RedBalance) Name() string { return "redbalance" }
