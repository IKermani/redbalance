// Package redbalance shuffles A, AAAA and MX records.
package redbalance

import (
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"time"
)

const (
	randomShufflePolicy      = "round_robin"
	weightedRoundRobinPolicy = "weighted"
)

type Redis struct {
	Next plugin.Handler

	client  *redis.Client
	options *redis.Options

	addr string
	idle int
	// Testing.
	now func() time.Time
}

// New returns a new initialized redis.Client.
func newRedis() *Redis {
	return &Redis{
		addr:    "127.0.0.1:6379",
		idle:    10,
		client:  &redis.Client{},
		options: &redis.Options{},
	}
}

// RedBalanceResponseWriter is a response writer that shuffles A, AAAA and MX records.
type RedBalanceResponseWriter struct {
	dns.ResponseWriter
	shuffle func(*dns.Msg) *dns.Msg
}

// WriteMsg implements the dns.ResponseWriter interface.
func (r *RedBalanceResponseWriter) WriteMsg(res *dns.Msg) error {
	if res.Rcode != dns.RcodeSuccess {
		return r.ResponseWriter.WriteMsg(res)
	}

	//if res.Question[0].Qtype == dns.TypeAXFR || res.Question[0].Qtype == dns.TypeIXFR {
	//	return r.ResponseWriter.WriteMsg(res)
	//}

	return r.ResponseWriter.WriteMsg(r.shuffle(res))
}

// Write implements the dns.ResponseWriter interface.
func (r *RedBalanceResponseWriter) Write(buf []byte) (int, error) {
	// Should we pack and unpack here to fiddle with the packet... Not likely.
	log.Warning("RedBalance called with Write: not shuffling records")
	n, err := r.ResponseWriter.Write(buf)
	return n, err
}
