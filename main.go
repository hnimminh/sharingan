package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

const (
	_SNAPLEN   = 262144 // The same default as tcpdump.
	_ELSFILTER = "tcp and port 8021"
	_IPXFILTER = "(ip||ip6) and "
)

var (
	debug    bool
	ifname   string
	bpfilter string
)

type PacketInfo struct {
	SrcIP     string
	DstIP     string
	Transport string
	SrcPort   string
	DstPort   string
	AppBody   string
	Error     error
}

func (p PacketInfo) Stringify() string {
	if p.Error != nil {
		return fmt.Sprintf("%s:%s -> %s:%s %s ::  %s [error=%s]", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Transport, p.AppBody, p.Error)
	}
	return fmt.Sprintf("%s:%s -> %s:%s %s :: %s", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Transport, p.AppBody)
}

func init() {
	/******************* RUN VARIABLE *******************/
	flag.BoolVar(&debug, "debug", false, "sets log level to debug")
	flag.BoolVar(&debug, "d", false, "sets log level to debug")
	flag.StringVar(&ifname, "interface", "any", "network interface name, ex: eth0")
	flag.StringVar(&ifname, "i", "any", "network interface name, ex: eth0")
	flag.StringVar(&bpfilter, "bpfilter", "", "your custom network filter expression (BPF)")
	flag.StringVar(&bpfilter, "b", "", "your custom network filter expression (BPF)")
	flag.Parse()

	/******************* LOG CONFIG *******************/
	output := zerolog.ConsoleWriter{}
	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("[%4s]", i))
	}
	zlog.Logger = zlog.Output(
		zerolog.ConsoleWriter{
			Out:         os.Stderr,
			TimeFormat:  time.RFC3339,
			FormatLevel: output.FormatLevel,
			NoColor:     false},
	)
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

func main() {

	handle, err := pcap.OpenLive(ifname, _SNAPLEN, false, pcap.BlockForever)
	if err != nil {
		zlog.Fatal().Err(err).Str("module", "sharingan").Str("action", "capture").Msgf("error while capturing on dev [%s]", ifname)
	}
	defer handle.Close()

	// filtering capture targets
	if bpfilter == "" {
		bpfilter = _ELSFILTER
	}
	bpfstring := _IPXFILTER + bpfilter

	err = handle.SetBPFFilter(bpfstring)
	if err != nil {
		zlog.Fatal().Err(err).Str("module", "sharingan").Str("action", "bpfilter").Msgf("error while filtering package [%s]", bpfilter)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// get decoded packets through chann
	for packet := range packetSource.Packets() {
		//zlog.Info().Msgf("%s", packet)
		packetinfo := informatizePacket(packet).Stringify()
		zlog.Info().Msgf("%s", packetinfo)
	}
}

func informatizePacket(packet gopacket.Packet) PacketInfo {

	var (
		srcip     string
		dstip     string
		transport string = "UNDEF"
		srcport   string
		dstport   string
		payload   string
		err       error
	)

	// Network - IPv4/IPv6 Layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcip = ipv4.SrcIP.String()
		dstip = ipv4.DstIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			srcip = ipv6.SrcIP.String()
			dstip = ipv6.DstIP.String()
		}
	}

	// Transport - TCP/UDP Layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		transport = "TCP"
		tcp, _ := tcpLayer.(*layers.TCP)
		srcport = strconv.Itoa(int(tcp.SrcPort))
		dstport = strconv.Itoa(int(tcp.DstPort))
	} else {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			transport = "UDP"
			udp, _ := udpLayer.(*layers.UDP)
			srcport = strconv.Itoa(int(udp.SrcPort))
			dstport = strconv.Itoa(int(udp.DstPort))
		}
	}

	// Application Layer
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload = string(appLayer.LayerContents())
		//payload = string(appLayer.Payload())
	}

	// error collection
	if _err := packet.ErrorLayer(); _err != nil {
		err = _err.Error()
	}

	// return
	return PacketInfo{
		srcip,
		dstip,
		transport,
		srcport,
		dstport,
		payload,
		err,
	}
}
