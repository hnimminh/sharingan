package esl

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EslJsonEvent struct {
	EventName string `json:"Event-Name"`
	UniqueID  string `json:"Unique-ID"`
}

type EslXmlEvent struct {
	XMLName   xml.Name `xml:"event"`
	EventName string   `xml:"headers>Event-Name"`
	UniqueID  string   `xml:"headers>Unique-ID"`
}

type EslData struct {
	SrcIP     string
	DstIP     string
	SrcPort   string
	DstPort   string
	SeqNo     uint32
	Flag      string
	AppBody   string
	IsEvent   bool
	Error     error
	IsVerbose bool
}

// showevent, verbose bool
func (es EslData) Stringify(debug bool) (dline string) {
	if !debug && es.AppBody == "" {
		return
	}
	_tcpflag := "TCP|" + es.Flag + "|" + strconv.Itoa(int(es.SeqNo))

	_appbody := es.AppBody
	if !es.IsEvent {
		_appbody = "\n" + es.AppBody
	}

	dline = fmt.Sprintf("%s:%s -> %s:%s %s :: %s", es.SrcIP, es.SrcPort, es.DstIP, es.DstPort, _tcpflag, _appbody)
	if es.Error != nil {
		dline = dline + fmt.Sprintf(" \nError=\n%s", es.Error)
	}
	return
}

func Inspect(packet gopacket.Packet, verbose bool) (esldata EslData) {
	esldata.IsVerbose = verbose
	// Network - IPv4/IPv6 Layer
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		esldata.SrcIP = ipv4.SrcIP.String()
		esldata.DstIP = ipv4.DstIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ipv6, _ := ipv6Layer.(*layers.IPv6)
			esldata.SrcIP = ipv6.SrcIP.String()
			esldata.DstIP = ipv6.DstIP.String()
		}
	}

	// Transport - TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		esldata.SrcPort = strconv.Itoa(int(tcp.SrcPort))
		esldata.DstPort = strconv.Itoa(int(tcp.DstPort))
		esldata.SeqNo = tcp.Seq
		if tcp.ACK {
			esldata.Flag = "ACK"
		} else if tcp.SYN {
			esldata.Flag = "SYN"
		} else if tcp.FIN {
			esldata.Flag = "FIN"
		} else if tcp.RST {
			esldata.Flag = "RST"
		} else if tcp.URG {
			esldata.Flag = "URG"
		} else if tcp.PSH {
			esldata.Flag = "PSH"
		} else if tcp.ECE {
			esldata.Flag = "ECE"
		} else if tcp.CWR {
			esldata.Flag = "CWR"
		}
	}

	// Application Layer
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		// zlog.Trace().Msgf("APPLAYER %s", string(appLayer.Payload()))
		payload := string(appLayer.LayerContents())
		esldata.AppBody = payload
		esldata.IsEvent = true
		if !verbose {
			if strings.HasPrefix(payload, `Event-Name:`) {
				plnevt, _ := textproto.NewReader(
					bufio.NewReader(
						bytes.NewReader(
							appLayer.LayerContents()),
					),
				).ReadMIMEHeader()
				esldata.AppBody = "PLAIN-Event: " + plnevt.Get("Event-Name") + "/" + plnevt.Get("Unique-ID")
			} else if strings.HasPrefix(payload, `{"Event-Name":`) {
				var jsonevt EslJsonEvent
				json.Unmarshal(appLayer.LayerContents(), &jsonevt)
				esldata.AppBody = "JSON-Event: " + jsonevt.EventName + "/" + jsonevt.UniqueID
			} else if strings.HasPrefix(payload, `<event>`) {
				var xmlevt EslXmlEvent
				xml.Unmarshal(appLayer.LayerContents(), &xmlevt)
				esldata.AppBody = "XML-Event: " + xmlevt.EventName + "/" + xmlevt.UniqueID
			} else {
				esldata.IsEvent = false
			}
		}
	}

	// error collection
	if _err := packet.ErrorLayer(); _err != nil {
		esldata.Error = _err.Error()
	}

	return esldata
}
