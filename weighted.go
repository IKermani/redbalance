package redbalance

import (
	"crypto/md5"
	"fmt"
	"golang.org/x/net/idna"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/smallnest/weighted"
)

const (
	SUFFIX = "suffix"
	PREFIX = "prefix"
	FQDN   = "fqdn"
)

type (
	// "weighted-round-robin" policy specific data
	weightedRR struct {
		fileName   string
		reload     time.Duration
		md5sum     [md5.Size]byte
		sniServers []*weightItem
		domains    map[domain]matchPattern
		rrw        weighted.RRW
		randomGen
		mutex sync.Mutex
	}
	domain       string
	matchPattern string
	// Per domain weights
	weights []*weightItem
	// Weight assigned to an address
	weightItem struct {
		address net.IP
		value   uint8
	}
	// Random uint generator
	randomGen interface {
		randInit()
		randUint(limit uint) uint
	}
)

// Domain validator
func (d *domain) isValid() error {
	// use idna to validate domain
	_, err := idna.Lookup.ToASCII(string(*d))
	return err
}

// Matching pattern validator
func (m *matchPattern) isValid() error {
	// matching pattern should only be one of SUFFIX, PREFIX or FQDN
	if *m != SUFFIX && *m != PREFIX && *m != FQDN {
		return fmt.Errorf("invalid matching pattern: %s", *m)
	}
	return nil
}

// Random uint generator
type randomUint struct {
	rn *rand.Rand
}

func (r *randomUint) randInit() {
	r.rn = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func (r *randomUint) randUint(limit uint) uint {
	return uint(r.rn.Intn(int(limit)))
}

func weightedShuffle(res *dns.Msg, w *weightedRR) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(res)

	switch res.Question[0].Qtype {
	case dns.TypeA:
		domain := res.Question[0].Name
		m = w.weightedRoundRobin(domain, m)
	}
	return m
}

func weightedOnStartUp(w *weightedRR, stopReloadChan chan bool) error {
	err := w.updateDNSMapping()
	if err != nil {
		return plugin.Error("redbalance", err)
	}
	err = w.updateSNIServerBandwidth()
	if err != nil {
		return plugin.Error("redbalance", err)
	}

	// start periodic weight file reload go routine
	w.periodicWeightUpdate(stopReloadChan)
	return nil
}

func createWeightedFuncs(weightFileName string,
	reload time.Duration) *lbFuncs {
	lb := &lbFuncs{
		weighted: &weightedRR{
			fileName:  weightFileName,
			reload:    reload,
			randomGen: &randomUint{},
		},
	}
	lb.weighted.randomGen.randInit()

	lb.shuffleFunc = func(res *dns.Msg) *dns.Msg {
		return weightedShuffle(res, lb.weighted)
	}

	stopReloadChan := make(chan bool)

	lb.onStartUpFunc = func() error {
		return weightedOnStartUp(lb.weighted, stopReloadChan)
	}

	lb.onShutdownFunc = func() error {
		// stop periodic weigh reload go routine
		close(stopReloadChan)
		return nil
	}
	return lb
}

func (w *weightedRR) weightedRoundRobin(domain string, r *dns.Msg) *dns.Msg {
	for d, pattern := range w.domains {
		if matchDomainPattern(domain, string(d), string(pattern)) {
			selectedServer := w.lvsRoundRobin()
			if selectedServer != nil {
				m := new(dns.Msg)
				m.SetReply(r)
				hdr := dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
				m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: selectedServer.address}}
				return m
			}
		}
	}

	return nil
}

// Domain matching logic
func matchDomainPattern(domain, pattern, matchType string) bool {
	switch matchType {
	case SUFFIX:
		return strings.HasSuffix(domain, pattern)
	case PREFIX:
		return strings.HasPrefix(domain, pattern)
	case FQDN:
		return domain == pattern
	default:
		return false
	}
}

// LVS based weighted round-robin
func (w *weightedRR) lvsRoundRobin() *weightItem {
	rrw := &weighted.RRW{}
	for _, sniServer := range w.sniServers {
		rrw.Add(sniServer, int(sniServer.value))
	}
	selected := rrw.Next()
	if selected != nil {
		return selected.(*weightItem)
	}
	return nil
}

// Move the next expected address to the first position in the result list
//func (w *weightedRR) setTopRecord(address []dns.RR) {
//	itop := w.topAddressIndex(address)
//
//	if itop < 0 {
//		// internal error
//		return
//	}
//
//	if itop != 0 {
//		// swap the selected top entry with the actual one
//		address[0], address[itop] = address[itop], address[0]
//	}
//}

// Compute the top (first) address index
//func (w *weightedRR) topAddressIndex(address []dns.RR) int {
//	w.mutex.Lock()
//	defer w.mutex.Unlock()
//
//	// Determine the weight value for each address in the answer
//	var wsum uint
//	type waddress struct {
//		index  int
//		weight uint8
//	}
//	weightedAddr := make([]waddress, len(address))
//	for i, ar := range address {
//		wa := &weightedAddr[i]
//		wa.index = i
//		wa.weight = 1 // default weight
//		var ip net.IP
//		switch ar.Header().Rrtype {
//			case dns.TypeA:
//				ip = ar.(*dns.A).A
//			case dns.TypeAAAA:
//				ip = ar.(*dns.AAAA).AAAA
//		}
//		ws := w.domains[ar.Header().Name]
//		for _, w := range ws {
//			if w.address.Equal(ip) {
//				wa.weight = w.value
//				break
//			}
//		}
//		wsum += uint(wa.weight)
//	}
//
//	// Select the first (top) IP
//	sort.Slice(weightedAddr, func(i, j int) bool {
//		return weightedAddr[i].weight > weightedAddr[j].weight
//	})
//	v := w.randUint(wsum)
//	var psum uint
//	for _, wa := range weightedAddr {
//		psum += uint(wa.weight)
//		if v < psum {
//			return wa.index
//		}
//	}
//
//	// we should never reach this
//	log.Errorf("Internal error: cannot find top address (randv:%v wsum:%v)", v, wsum)
//	return -1
//}

// Start go routine to update weights from the weight file periodically
func (w *weightedRR) periodicWeightUpdate(stopReload <-chan bool) {
	if w.reload == 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(w.reload)

		for {
			select {
			case <-stopReload:
				return
			case <-ticker.C:
				err := w.updateDNSMapping()
				if err != nil {
					log.Error(err)
				}
				err = w.updateSNIServerBandwidth()
				if err != nil {
					log.Error(err)
				}
			}
		}
	}()
}

func (w *weightedRR) updateDNSMapping() error {
	// Connect to your Redis instance here.
	//rdb := redis.NewClient(&redis.Options{
	//	Addr:     "127.0.0.1:6379", // replace with your Redis address
	//	Password: "",               // replace with your password if needed
	//	DB:       0,                // use default DB
	//})

	// Fetch data from Redis.
	result, err := rdb.client.HGetAll(ctx, "domains").Result()
	if err != nil {
		return err
	}

	// If the result is empty, return an error
	if len(result) == 0 {
		log.Warningf("domains is empty in Redis. Retrying in %v", w.reload)
	}

	// convert the result to a map[domain]matchPattern
	_domains := make(map[domain]matchPattern)
	for _domain, _matchingPattern := range result {
		_domains[domain(_domain)] = matchPattern(_matchingPattern)
	}

	// validate all domains
	for _domain := range _domains {
		if err := _domain.isValid(); err != nil {
			return err
		}
	}

	// validate all matching patterns
	for _matchingPattern := range _domains {
		if err := _matchingPattern.isValid(); err != nil {
			return err
		}
	}

	w.mutex.Lock()
	w.domains = _domains
	w.mutex.Unlock()

	return nil
}

func (w *weightedRR) updateSNIServerBandwidth() error {
	// Connect to your Redis instance here.
	//rdb := redis.NewClient(&redis.Options{
	//	Addr:     "localhost:6379", // replace with your Redis address
	//	Password: "",               // replace with your password if needed
	//	DB:       0,                // use default DB
	//})

	// Fetch data from Redis.
	result, err := rdb.client.HGetAll(ctx, "sni_server_bandwidth").Result()
	if err != nil {
		return err
	}

	// If the result is empty, return an error
	if len(result) == 0 {
		log.Warningf("sni_server_bandwidth is empty in Redis. Retrying in %v", w.reload)
	}

	// convert the result to a []*weightedItem
	_sniServers := make([]*weightItem, 0)
	for key, value := range result {
		ip := net.ParseIP(key)
		if ip == nil {
			return fmt.Errorf("wrong IP address:\"%s\" in Redis", key)
		}
		weight, err := strconv.ParseUint(value, 10, 8)
		if err != nil || weight == 0 {
			return fmt.Errorf("wrong weight value:\"%s\" in Redis", value)
		}
		witem := &weightItem{address: ip, value: uint8(weight)}
		_sniServers = append(_sniServers, witem)
	}

	w.mutex.Lock()
	w.sniServers = _sniServers
	w.mutex.Unlock()
	return nil
}
