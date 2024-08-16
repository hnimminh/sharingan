package ngcp

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// packet infomation structure
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
		return fmt.Sprintf("%s:%s -> %s:%s %s :: %s [error=%s]", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Transport, p.AppBody, p.Error)
	}
	return fmt.Sprintf("%s:%s -> %s:%s %s :: %s", p.SrcIP, p.SrcPort, p.DstIP, p.DstPort, p.Transport, p.AppBody)
}

func informatizePacket(packet gopacket.Packet) PacketInfo {

	var (
		srcip     string
		dstip     string
		transport string = "UNSUPPORTED"
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
