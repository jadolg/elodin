package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"elodin.bench/internal/dnswire"
)

// The DNSSEC survey asks real names through elodin with validation on, asks a
// reference validating resolver the same thing, and compares the rcode and the
// AD bit.
//
// It is here because neither test layer can answer the question it answers.
// Both work from fixtures, so both can show that a forged answer is refused and
// neither can show that validation leaves working names working. A validator
// that refused everything would pass the whole suite.

type verdict struct {
	domain string
	// wantBogus marks a deliberately broken zone, which must be refused.
	wantBogus bool

	elodinRcode int
	elodinAD    bool
	elodinErr   error

	refRcode int
	refAD    bool
	refErr   error
}

func (v verdict) agrees() bool {
	return v.elodinRcode == v.refRcode && v.elodinAD == v.refAD
}

func (h *harness) dnssecSurvey(reference string) (string, error) {
	domains, err := readDomains(filepath.Join(h.root, "bench", "domains.txt"))
	if err != nil {
		return "", err
	}

	s, err := h.start(serverOpts{
		name:   "survey",
		dnssec: true,
		// The cache is on because zone keys are cached with it: without that
		// every name re-walks the chain from the root, which is enough traffic
		// for a public resolver to start dropping it.
		cache:        true,
		attempts:     2,
		upstreamAddr: reference,
	})
	if err != nil {
		return "", err
	}
	defer s.stop()

	// Validation walks the chain from the root for the first name in a zone, so
	// a cold start against a hundred names is a lot of upstream work. Asking a
	// few at a time keeps it from looking like an attack to the resolver while
	// still finishing in reasonable time.
	results := make([]verdict, len(domains))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d domain) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			v := verdict{domain: d.name, wantBogus: d.bogus}
			v.elodinRcode, v.elodinAD, v.elodinErr = askDO(s.dnsAddr, d.name)
			v.refRcode, v.refAD, v.refErr = askDO(reference, d.name)
			results[i] = v
		}(i, d)
	}
	wg.Wait()

	return renderSurvey(results, reference), nil
}

type domain struct {
	name  string
	bogus bool
}

func readDomains(path string) ([]domain, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []domain
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		d := domain{name: fields[0]}
		if len(fields) > 1 && fields[1] == "bogus" {
			d.bogus = true
		}
		out = append(out, d)
	}
	return out, sc.Err()
}

// askDO asks one name with the DO bit set, retrying once: a single lost UDP
// datagram against a public resolver is not a verdict.
func askDO(addr, name string) (rcode int, ad bool, err error) {
	for attempt := range 2 {
		rcode, ad, err = askDOOnce(addr, name)
		if err == nil {
			return rcode, ad, nil
		}
		if attempt == 0 {
			time.Sleep(500 * time.Millisecond)
		}
	}
	return rcode, ad, err
}

func askDOOnce(addr, name string) (int, bool, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()

	id := uint16(rand.Uint32())
	q := dnswire.QueryDO(id, name, dnswire.TypeA, 1232)
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return 0, false, err
	}
	if _, err := conn.Write(q); err != nil {
		return 0, false, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return 0, false, err
		}
		reply, err := dnswire.ParseReply(buf[:n])
		if err != nil {
			return 0, false, err
		}
		if reply.ID != id {
			continue
		}
		return reply.Rcode, reply.AD, nil
	}
}

func renderSurvey(results []verdict, reference string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# elodin DNSSEC survey\n\n")
	fmt.Fprintf(&sb, "%s\n\n", describeMachine())
	fmt.Fprintf(&sb, "%d names asked through elodin with validation on, and asked again of %s.\n\n",
		len(results), reference)

	var (
		agreed, disagreed, failed int
		bogusRefused, bogusServed int
		adHere, adThere           int
		mismatches                []verdict
		errored                   []verdict
	)
	for _, v := range results {
		if v.elodinErr != nil || v.refErr != nil {
			failed++
			errored = append(errored, v)
			continue
		}
		if v.wantBogus {
			if v.elodinRcode == 2 {
				bogusRefused++
			} else {
				bogusServed++
				mismatches = append(mismatches, v)
			}
			continue
		}
		if v.elodinAD {
			adHere++
		}
		if v.refAD {
			adThere++
		}
		if v.agrees() {
			agreed++
		} else {
			disagreed++
			mismatches = append(mismatches, v)
		}
	}

	fmt.Fprintf(&sb, "| | |\n|---|---|\n")
	fmt.Fprintf(&sb, "| names agreeing on rcode and AD | %d |\n", agreed)
	fmt.Fprintf(&sb, "| names differing | %d |\n", disagreed)
	fmt.Fprintf(&sb, "| authenticated here / by the reference | %d / %d |\n", adHere, adThere)
	fmt.Fprintf(&sb, "| deliberately broken, refused | %d |\n", bogusRefused)
	fmt.Fprintf(&sb, "| deliberately broken, served anyway | %d |\n", bogusServed)
	fmt.Fprintf(&sb, "| unanswered by one side or the other | %d |\n\n", failed)

	if len(mismatches) > 0 {
		sb.WriteString("Where they differ:\n\n")
		sb.WriteString("| name | elodin | reference |\n|---|---|---|\n")
		for _, v := range mismatches {
			fmt.Fprintf(&sb, "| %s | %s | %s |\n", v.domain,
				describeAnswer(v.elodinRcode, v.elodinAD), describeAnswer(v.refRcode, v.refAD))
		}
		sb.WriteString("\n")
	}
	if len(errored) > 0 {
		sb.WriteString("Unanswered:\n\n")
		for _, v := range errored {
			reason := v.elodinErr
			side := "elodin"
			if reason == nil {
				reason, side = v.refErr, "reference"
			}
			fmt.Fprintf(&sb, "- %s (%s: %v)\n", v.domain, side, reason)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func rcodeName(rc int) string {
	switch rc {
	case 0:
		return "noerror"
	case 2:
		return "servfail"
	case 3:
		return "nxdomain"
	case 5:
		return "refused"
	default:
		return fmt.Sprintf("rcode%d", rc)
	}
}

func describeAnswer(rcode int, ad bool) string {
	name := rcodeName(rcode)
	if ad {
		return name + " + AD"
	}
	return name
}
