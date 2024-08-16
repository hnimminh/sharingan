package main

import (
	"flag"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	esl "github.com/hnimminh/sharingan/esl"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const (
	_SNAPLEN = 262144 // The same default as tcpdump.
	_TCP     = "TCP"
	_UDP     = "UDP"

	_ELS_FILTER  = "tcp and port 8021"
	_NGCP_FILTER = "udp and port 22222"
	_IP_FILTER   = "(ip||ip6) and "
)

var (
	debug        bool
	verbose      bool
	jsonlog      bool
	systlog      bool
	ifname       string
	_appfiter    string
	appfilter    string
	bpfilter     string
	bpfstring    string
	appfiltermap map[string]string = map[string]string{
		"ESL":  _ELS_FILTER,
		"NGCP": _NGCP_FILTER,
	}
)

func init() {
	/******************* RUN VARIABLE *******************/
	flag.BoolVar(&debug, "debug", false, "sets log level to debug")
	flag.BoolVar(&debug, "d", false, "sets log level to debug")
	flag.BoolVar(&verbose, "verbose", false, "verbosely inspect packet")
	flag.BoolVar(&systlog, "syslog", false, "send to local system log")
	flag.BoolVar(&systlog, "s", false, "send to local system log")
	flag.BoolVar(&jsonlog, "jsonlog", false, "log with json format, default is text")
	flag.BoolVar(&jsonlog, "j", false, "log with json format, default is text")
	flag.StringVar(&ifname, "interface", "any", "network interface name, ex: eth0")
	flag.StringVar(&ifname, "i", "any", "network interface name, ex: eth0")
	flag.StringVar(&_appfiter, "appfiter", "", "application that you want to observation")
	flag.StringVar(&_appfiter, "a", "", "application that you want to observation")
	flag.StringVar(&bpfilter, "bpfilter", "", "your custom network filter expression (BPF), overide appfiter default filter")
	flag.StringVar(&bpfilter, "b", "", "your custom network filter expression (BPF), overide appfiter default filter")
	flag.Parse()

	/******************* LOG CONFIG *******************/
	if !jsonlog {
		output := io.MultiWriter(os.Stdout)
		if systlog {
			zsyslog, _ := syslog.New(syslog.LOG_LOCAL7|syslog.LOG_DEBUG, "sharingan")
			output = io.MultiWriter(os.Stdout, zsyslog)
		}
		zlog.Logger = zlog.Output(
			zerolog.ConsoleWriter{
				Out:        output,
				TimeFormat: time.RFC3339,
				FormatLevel: func(i interface{}) string {
					return strings.ToUpper(fmt.Sprintf("[%4s]", i))
				},
				NoColor: true},
		)
	}
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		zlog.Logger = zlog.With().Caller().Logger()
	}

	/******************* VALIDATION *******************/
	appfilter = appfiltermap[strings.ToUpper(_appfiter)]
	if appfilter == "" && bpfilter == "" {
		if _appfiter == "" {
			zlog.Fatal().Str("module", "sharingan").Msg("atleast <appfilter> or <bgpfilter> must be set")
		}
		zlog.Fatal().Str("module", "sharingan").Msg("unsupport application to filter; current support <ESL>, <NGCP>")
	}

	bpfstring = _IP_FILTER + appfilter
	if bpfilter != "" {
		bpfstring = _IP_FILTER + bpfilter
	}
}

func main() {
	handle, err := pcap.OpenLive(ifname, _SNAPLEN, false, pcap.BlockForever)
	if err != nil {
		zlog.Fatal().Err(err).Str("module", "sharingan").Str("action", "capture").Msgf("error while capturing on dev [%s]", ifname)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(bpfstring)
	if err != nil {
		zlog.Fatal().Err(err).Str("module", "sharingan").Str("action", "bpfilter").Msgf("error while filtering package [%s]", bpfilter)
	}

	packetsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetsrc.Packets() {
		packetstr := esl.Inspect(packet, verbose).Stringify(debug)
		if packetstr != "" {
			zlog.Info().Msg(packetstr)
		}
	}
}
