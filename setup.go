package redbalance

import (
	"context"
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/redis/go-redis/v9"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("redbalance")
var ctx = context.Background()
var rdb = newRedis()

func init() { plugin.Register("redbalance", setup) }

type lbFuncs struct {
	shuffleFunc    func(*dns.Msg) *dns.Msg
	onStartUpFunc  func() error
	onShutdownFunc func() error
	weighted       *weightedRR // used in unit tests only
}

func setup(c *caddy.Controller) error {
	//shuffleFunc, startUpFunc, shutdownFunc, err := parse(c)
	lb, err := parse(c)
	if err != nil {
		return plugin.Error("redbalance", err)
	}
	if lb.onStartUpFunc != nil {
		c.OnStartup(lb.onStartUpFunc)
	}
	if lb.onShutdownFunc != nil {
		c.OnShutdown(lb.onShutdownFunc)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return RedBalance{Next: next, shuffle: lb.shuffleFunc, redisDB: rdb}
	})

	return nil
}

// func parse(c *caddy.Controller) (string, *weightedRR, error) {
func parse(c *caddy.Controller) (*lbFuncs, error) {

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) == 0 {
			return nil, c.ArgErr()
		}
		switch args[0] {
		case weightedRoundRobinPolicy:
			if len(args) < 2 {
				return nil, c.Err("missing key prefix")
			}

			if len(args) > 2 {
				return nil, c.Err("unexpected argument(s)")
			}

			prefixName := args[1]

			reload := 30 * time.Second // default reload period

			for c.NextBlock() {
				switch c.Val() {
				case "address":
					a := c.RemainingArgs()
					if len(a) < 1 {
						return nil, c.Err("address value is missing")
					}
					if len(a) > 1 {
						return nil, c.Err("unexpected argument")
					}
					host, port, err := net.SplitHostPort(a[0])
					if err != nil && strings.Contains(err.Error(), "missing port in address") {
						if x := net.ParseIP(args[0]); x == nil {
							return nil, fmt.Errorf("failed to parse IP: %s", args[0])
						}
						rdb.options.Addr = net.JoinHostPort(a[0], "6379")
						continue
					}
					if err != nil {
						return nil, err
					}

					// host should be a valid IP
					if net.ParseIP(host) == nil {
						return nil, c.Errf("invalid address '%s'", a[0])
					}

					// port should be a valid port
					if _, err := strconv.Atoi(port); err != nil {
						return nil, c.Errf("invalid port '%s'", port)
					}

					rdb.options.Addr = a[0]
				//case "username":
				//	u := c.RemainingArgs()
				//	if len(u) < 1 {
				//		return nil, nil, c.Err("username value is missing")
				//	}
				//	if len(u) > 1 {
				//		return nil, nil, c.Err("unexpected argument")
				//	}
				//	_redis.options.Username = u[0]
				//case "password":
				//	p := c.RemainingArgs()
				//	if len(p) < 1 {
				//		return nil, nil, c.Err("password value is missing")
				//	}
				//	if len(p) > 1 {
				//		return nil, nil, c.Err("unexpected argument")
				//	}
				//	_redis.options.Password = p[0]
				//case "db":
				//	d := c.RemainingArgs()
				//	if len(d) < 1 {
				//		return nil, nil, c.Err("db value is missing")
				//	}
				//	if len(d) > 1 {
				//		return nil, nil, c.Err("unexpected argument")
				//	}
				//	redisDB, err := strconv.Atoi(d[0])
				//	if err != nil {
				//		return nil, nil, c.Errf("invalid db '%s'", d[0])
				//	}
				//	if redisDB < 0 {
				//		return nil, nil, c.Errf("invalid db '%s'", d[0])
				//	}
				//	_redis.options.DB = redisDB
				case "reload":
					t := c.RemainingArgs()
					if len(t) < 1 {
						return nil, c.Err("reload duration value is missing")
					}
					if len(t) > 1 {
						return nil, c.Err("unexpected argument")
					}
					var err error
					reload, err = time.ParseDuration(t[0])
					if err != nil {
						return nil, c.Errf("invalid reload duration '%s'", t[0])
					}
				default:
					return nil, c.Errf("unknown property '%s'", c.Val())
				}
			}
			rdb.client = redis.NewClient(rdb.options)
			return createWeightedFuncs(prefixName, reload), nil
		default:
			return nil, fmt.Errorf("unknown policy: %s", args[0])
		}
	}
	return nil, c.ArgErr()
}
