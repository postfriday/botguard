// Command botctl is the operator CLI for botguard. It talks directly to the
// SQLite store (no daemon connection needed), so it can run inside the same
// container as a one-shot.
//
//	botctl status
//	botctl report --since 24h [--format md|csv]
//	botctl whois <ip>
//	botctl unblock <ip> [--reason "false positive"]
//	botctl block   <ip> [--reason "manual"]
//	botctl rules   list
//	botctl purge
package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/postfriday/botguard/internal/config"
	"github.com/postfriday/botguard/internal/store"
)

func main() {
	cfgPath := flag.String("config", "/etc/botguard/botguard.yaml", "path to config file")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	cfg, _, err := config.Load(*cfgPath)
	if err != nil {
		die("config: %v", err)
	}
	st, err := store.Open(cfg.Cache.Path)
	if err != nil {
		die("store: %v", err)
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	switch args[0] {
	case "status":
		runStatus(ctx, st)
	case "report":
		runReport(ctx, st, args[1:])
	case "whois":
		if len(args) < 2 {
			die("whois requires an IP")
		}
		runWhois(ctx, st, args[1])
	case "unblock":
		if len(args) < 2 {
			die("unblock requires an IP")
		}
		reason := joinAfter(args, 2)
		if err := st.SetOverride(ctx, args[1], "allow", reason); err != nil {
			die("unblock: %v", err)
		}
		fmt.Printf("ok: %s overridden to allow\n", args[1])
	case "block":
		if len(args) < 2 {
			die("block requires an IP")
		}
		reason := joinAfter(args, 2)
		if err := st.SetOverride(ctx, args[1], "deny", reason); err != nil {
			die("block: %v", err)
		}
		fmt.Printf("ok: %s overridden to deny\n", args[1])
	case "drop-override":
		if len(args) < 2 {
			die("drop-override requires an IP")
		}
		if err := st.DropOverride(ctx, args[1]); err != nil {
			die("drop-override: %v", err)
		}
		fmt.Printf("ok: override removed for %s\n", args[1])
	case "purge":
		n, err := st.PurgeExpired(ctx)
		if err != nil {
			die("purge: %v", err)
		}
		fmt.Printf("ok: purged %d expired rows\n", n)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `botctl — operator CLI for botguard

Subcommands:
  status                       Print store stats and config summary.
  report --since 24h [--format md|csv]
                              Domain-grouped block report.
  whois <ip>                   Show cached info about a single IP.
  unblock <ip> [reason...]     Force allow override for an IP.
  block <ip> [reason...]       Force deny override (added to blocklist).
  drop-override <ip>           Remove any manual override for an IP.
  purge                        Drop expired ip_cache rows.

Flags:
  -config <path>               Path to botguard.yaml.`)
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func joinAfter(args []string, i int) string {
	if i >= len(args) {
		return ""
	}
	return strings.Join(args[i:], " ")
}

func runStatus(ctx context.Context, st *store.Store) {
	db := st.DB()
	var cached, blocked, allowed, neutral int64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_cache`).Scan(&cached)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_cache WHERE decision='deny'`).Scan(&blocked)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_cache WHERE decision='allow'`).Scan(&allowed)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ip_cache WHERE decision='neutral'`).Scan(&neutral)

	var hits int64
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM block_events`).Scan(&hits)

	var first, last int64
	_ = db.QueryRowContext(ctx, `SELECT MIN(ts), MAX(ts) FROM block_events`).Scan(&first, &last)

	fmt.Println("botguard status")
	fmt.Printf("  cached IPs:       %d\n", cached)
	fmt.Printf("    decision=deny:  %d\n", blocked)
	fmt.Printf("    decision=allow: %d\n", allowed)
	fmt.Printf("    decision=neutr: %d\n", neutral)
	fmt.Printf("  block events:     %d\n", hits)
	if first > 0 {
		fmt.Printf("  first event:      %s\n", time.Unix(first, 0).Format(time.RFC3339))
		fmt.Printf("  last  event:      %s\n", time.Unix(last, 0).Format(time.RFC3339))
	}
}

func runReport(ctx context.Context, st *store.Store, args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	since := fs.String("since", "24h", "time window, e.g. 24h, 7d (with d as 24h)")
	format := fs.String("format", "md", "output format: md|csv")
	_ = fs.Parse(args)

	dur, err := parseDuration(*since)
	if err != nil {
		die("since: %v", err)
	}
	cutoff := time.Now().Add(-dur).Unix()

	rows, err := st.DB().QueryContext(ctx, `
		SELECT COALESCE(rule_pattern, '(none)') AS pattern,
		       COUNT(DISTINCT ip)               AS unique_ips,
		       COUNT(*)                         AS hits,
		       MIN(ts), MAX(ts)
		  FROM block_events WHERE ts >= ?
		 GROUP BY pattern
		 ORDER BY hits DESC`, cutoff)
	if err != nil {
		die("query: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type r struct {
		pattern     string
		uniqueIPs   int
		hits        int
		first, last int64
	}
	var data []r
	for rows.Next() {
		var x r
		if err := rows.Scan(&x.pattern, &x.uniqueIPs, &x.hits, &x.first, &x.last); err != nil {
			die("scan: %v", err)
		}
		data = append(data, x)
	}

	switch *format {
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"pattern", "unique_ips", "hits", "first", "last"})
		for _, x := range data {
			_ = w.Write([]string{
				x.pattern,
				fmt.Sprintf("%d", x.uniqueIPs),
				fmt.Sprintf("%d", x.hits),
				time.Unix(x.first, 0).Format(time.RFC3339),
				time.Unix(x.last, 0).Format(time.RFC3339),
			})
		}
		w.Flush()
	default:
		fmt.Printf("# botguard report — last %s\n\n", dur)
		fmt.Println("| Pattern | Unique IPs | Hits | First | Last |")
		fmt.Println("|---|---:|---:|---|---|")
		for _, x := range data {
			fmt.Printf("| %s | %d | %d | %s | %s |\n",
				x.pattern, x.uniqueIPs, x.hits,
				time.Unix(x.first, 0).Format(time.RFC3339),
				time.Unix(x.last, 0).Format(time.RFC3339))
		}
		if len(data) == 0 {
			fmt.Println("\n_no events in window_")
		}
	}
}

func runWhois(ctx context.Context, st *store.Store, ip string) {
	rec, err := st.GetIP(ctx, ip)
	if err != nil {
		die("get: %v", err)
	}
	if rec == nil {
		fmt.Printf("no cache entry for %s\n", ip)
		return
	}
	fmt.Printf("ip:           %s\n", rec.IP)
	fmt.Printf("hostname:     %s\n", rec.Hostname)
	fmt.Printf("verification: %s\n", rec.Verification)
	fmt.Printf("decision:     %s\n", rec.Decision)
	fmt.Printf("rule:         %s\n", rec.RulePattern)
	fmt.Printf("ua:           %s\n", rec.UA)
	fmt.Printf("hits:         %d\n", rec.HitCount)
	fmt.Printf("checked_at:   %s\n", rec.CheckedAt.Format(time.RFC3339))
	fmt.Printf("expires_at:   %s\n", rec.ExpiresAt.Format(time.RFC3339))
	if act, _ := st.Override(ctx, ip); act != "" {
		fmt.Printf("override:     %s\n", act)
	}
}

// parseDuration accepts standard Go durations plus "<N>d" for days.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		d, err := time.ParseDuration(days + "h")
		if err != nil {
			return 0, err
		}
		return d * 24, nil
	}
	return time.ParseDuration(s)
}
