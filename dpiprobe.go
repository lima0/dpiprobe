package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/refraction-networking/utls"
	"golang.org/x/net/idna"
	"golang.org/x/net/ipv4"
)

func main() {
	maxTTL := flag.Uint("ttl", 30, "Maximum number of hops.")
	connectionMode := flag.String("mode", "", "Connection mode: (syn|http|https).")
	disableIPPTRLookup := flag.Bool("n", false, "Disable IP PTR lookup.")
	timeoutSeconds := flag.Uint("t", 15, "Timeout for each hop.")
	port := flag.Uint("port", 0, "Port number.")
	flag.Parse()

	switch *connectionMode {
	case "http", "syn":
		if *port == 0 {
			*port = 80
		}
	case "https":
		if *port == 0 {
			*port = 443
		}
	default:
		fmt.Printf("Invalid mode: (%s) \nUsage: dpiprobe --mode (http or https or syn) \n", *connectionMode)
		os.Exit(1)
	}

	domain := flag.Arg(0)
	if domain == "" {
		fmt.Printf("Specify blocked domain to probe with http.\n")
		os.Exit(1)
	}

	encodedDomain, err := idna.ToASCII(domain)
	if err != nil {
		fmt.Printf("Unable to ascii encode the given domain: %s", err)
		os.Exit(1)
	}

	if *maxTTL < 1 {
		fmt.Printf("Maximum number of hops must be 1 or greater.\n")
		os.Exit(1)
	}

	maxTTLByte := uint8(*maxTTL)

	if *maxTTL > 255 {
		fmt.Printf("Maximum number of hops cannot exceed 255.\n")
		os.Exit(1)
	}

	if *timeoutSeconds < 1 {
		fmt.Printf("Timeout must be greater than 0.\n")
		os.Exit(1)
	}

	targetIP, err := net.ResolveIPAddr("ip", encodedDomain)
	if err != nil {
		fmt.Printf("Failed to resolve target domain to IP address: %s\n", err)
		os.Exit(2)
	}

	outgoingPcapInterfaceName, outgoingIP, err := findOutgoingPcapInterfaceNameAndIP(targetIP)
	if err != nil {
		fmt.Printf("Outgoing interface lookup error: %s\n", err)
		os.Exit(2)
	}

	livePacketSource, err := startPacketCapture(outgoingPcapInterfaceName, targetIP, *port)
	if err != nil {
		fmt.Printf("Failed to start packet capture on interface '%s': %s\n", outgoingPcapInterfaceName, err)
		os.Exit(3)
	}
	defer livePacketSource.Close()

	var targetConn net.Conn = nil

	var frame gopacket.Packet
	var firstIPPacket *layers.IPv4
	var firstAckTCPPacket *layers.TCP
	var firstIcmpPacket *layers.ICMPv4
	var firstSourceMac *net.HardwareAddr
	var firstTargetMac *net.HardwareAddr

	targetConn, err = net.Dial("tcp", net.JoinHostPort(targetIP.String(), fmt.Sprintf("%d", *port)))
	if err != nil {
		fmt.Printf("Failed to establish connection to %s: %s\n", domain, err)
	}
	if err == nil {
		defer func() { _ = targetConn.Close() }()
	}

	select {
	case frame = <-livePacketSource.PacketChan:
		break
	case <-time.After(time.Second * 5):
		fmt.Printf("Timed out waiting to read the first SYN packet.\n")
		os.Exit(4)
	}

	firstEthernetPacket, _ := frame.LinkLayer().(*layers.Ethernet)
	firstLinuxSllPacket, _ := frame.LinkLayer().(*layers.LinuxSLL)

	if firstEthernetPacket != nil {
		firstSourceMac = &firstEthernetPacket.SrcMAC
		firstTargetMac = &firstEthernetPacket.DstMAC
	} else if firstLinuxSllPacket != nil {
		// Do nothing
	} else {
		fmt.Printf("Unsupported link-layer type: %T\n", frame.LinkLayer())
		os.Exit(3)
	}

	if targetConn != nil {
		select {
		case frame = <-livePacketSource.PacketChan:
			break
		case <-time.After(time.Second * 5):
			fmt.Printf("Timed out waiting to receive the first SYN-ACK packet.\n")
			os.Exit(4)
		}

		firstIPPacket = frame.NetworkLayer().(*layers.IPv4)
		firstAckTCPPacket, _ = frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
		firstIcmpPacket, _ = frame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

		if firstAckTCPPacket == nil {
			if firstIPPacket != nil && firstIcmpPacket != nil {
				fmt.Printf("* Received ICMP TTL exceeded from %s.\n", firstIPPacket.SrcIP.String())
			} else if frame != nil {
				fmt.Printf("* Received unexpected packet: %s\n", frame.TransportLayer())
				os.Exit(5)
			}
		} else if firstAckTCPPacket.RST {
			fmt.Printf("* Received TCP Reset.\n")
			firstAckTCPPacket = nil
		}
	}

	switch *connectionMode {
	case "http":
		fmt.Println("Running in HTTP mode")
		err = runHTTPGetTrace(
			firstSourceMac,
			outgoingIP,
			firstTargetMac,
			targetIP,
			encodedDomain,
			firstAckTCPPacket.DstPort,
			firstAckTCPPacket.Ack,
			firstAckTCPPacket.Seq+1,
			livePacketSource,
			maxTTLByte,
			*disableIPPTRLookup,
			*timeoutSeconds,
			int(*port))
	case "https":
		fmt.Println("Running in HTTPS ClientHello mode")
		// use uTLS library to create a google chrome fingerprinted clienthello using empty connection
		var conn net.Conn = nil
		uTLSConn := tls.UClient(conn, &tls.Config{ServerName: domain}, tls.HelloChrome_Auto)
		var err = uTLSConn.BuildHandshakeState()
		if err != nil {
			return
		}
		var rawClientHello = uTLSConn.HandshakeState.Hello.Raw
		var recordHeader = []byte{0x16, 0x03, 0x01}
		var recordHeaderBytes = make([]byte, 2)
		var clientHelloUInt16 = uint16(len(rawClientHello))
		binary.BigEndian.PutUint16(recordHeaderBytes, clientHelloUInt16)
		var fullClientHello = append(recordHeader, recordHeaderBytes...)
		fullClientHello = append(fullClientHello, rawClientHello...) // append record header + clienthello size to payload

		fmt.Printf("* TCP connection established. Performing HTTP GET traceroute.\n")
		err = runClientHellotrace(
			firstSourceMac,
			outgoingIP,
			firstTargetMac,
			targetIP,
			encodedDomain,
			firstAckTCPPacket.DstPort,
			firstAckTCPPacket.Ack,
			firstAckTCPPacket.Seq+1,
			livePacketSource,
			maxTTLByte,
			*disableIPPTRLookup,
			*timeoutSeconds,
			fullClientHello,
			int(*port))
	case "syn":
		fmt.Println("Running in TCP syn mode")
		if targetConn != nil {
			_ = targetConn.Close()

			for {
				select {
				case frame = <-livePacketSource.PacketChan:
					break
				case <-time.After(time.Second * time.Duration(*timeoutSeconds)):
					fmt.Printf("Timed out waiting to read FIN packet.\n")
					os.Exit(4)
				}

				tcpPacket, _ := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
				if tcpPacket.FIN {
					break
				}
			}
		}

		err = runTCPSynTrace(
			firstSourceMac,
			outgoingIP,
			firstTargetMac,
			targetIP,
			livePacketSource,
			maxTTLByte,
			*disableIPPTRLookup,
			*timeoutSeconds,
			int(*port))
	}

	if err != nil {
		fmt.Printf("* Probe failure: %s\n", err)
		os.Exit(6)
	}

	fmt.Printf("* Probe complete.\n")
}

func startPacketCapture(outgoingInterfaceName string, targetIP *net.IPAddr, port uint) (pcapSource *LivePacketSource, err error) {
	liveHandle, err := pcap.OpenLive(outgoingInterfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	targetIPInt := big.NewInt(0)
	targetIPInt.SetBytes(targetIP.IP.To4())
	targetIPHex := hex.EncodeToString(targetIPInt.Bytes())

	captureFilter := fmt.Sprintf(
		"(tcp and dst %s and dst port %d and tcp[tcpflags] & tcp-syn == tcp-syn) or"+
			" (tcp and src %s and port %d and (tcp[tcpflags] & (tcp-ack|tcp-rst|tcp-fin) != 0)) or"+
			" (icmp[icmptype] == icmp-timxceed and icmp[17] == 6 and icmp[24:4] == 0x%s and icmp[30:2] == %d)",
		targetIP.String(),
		port,
		targetIP.String(),
		port,
		targetIPHex,
		port)

	if err := liveHandle.SetBPFFilter(captureFilter); err != nil {
		liveHandle.Close()
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(liveHandle, liveHandle.LinkType())
	pcapSource = &LivePacketSource{PacketChan: packetSource.Packets(), PcapHandle: liveHandle}

	return pcapSource, nil
}

// LivePacketSource unexported
type LivePacketSource struct {
	PacketChan chan gopacket.Packet
	PcapHandle *pcap.Handle
}

// Close unexported
func (p *LivePacketSource) Close() {
	p.PcapHandle.Close()
}

func runHTTPGetTrace(
	sourceMac *net.HardwareAddr,
	sourceIP *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIP *net.IPAddr,
	domain string,
	sourcePort layers.TCPPort,
	tcpSeqNumber uint32,
	tcpAckNumber uint32,
	livePacketSource *LivePacketSource,
	maxTTL uint8,
	disableIPPTRLookup bool,
	timeoutSeconds uint,
	port int) error {

	return runTrace(
		tcpAckNumber,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIP.IP,
				DstIP:    targetIP.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: sourcePort,
				DstPort: layers.TCPPort(port),
				Seq:     tcpSeqNumber,
				Ack:     tcpAckNumber,
				Window:  1450,
				ACK:     true,
				PSH:     true,
			}
			tcpPayload := []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", domain))
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, tcpPayload); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTTL,
		disableIPPTRLookup,
		timeoutSeconds)
}

func runClientHellotrace(
	sourceMac *net.HardwareAddr,
	sourceIP *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIP *net.IPAddr,
	domain string,
	sourcePort layers.TCPPort,
	tcpSeqNumber uint32,
	tcpAckNumber uint32,
	livePacketSource *LivePacketSource,
	maxTTL uint8,
	disableIPPTRLookup bool,
	timeoutSeconds uint,
	rawClientHello []byte,
	port int) error {

	return runTrace(
		tcpAckNumber,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIP.IP,
				DstIP:    targetIP.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: sourcePort,
				DstPort: layers.TCPPort(port),
				Seq:     tcpSeqNumber,
				Ack:     tcpAckNumber,
				Window:  1450,
				ACK:     true,
				PSH:     true,
			}
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, rawClientHello); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTTL,
		disableIPPTRLookup,
		timeoutSeconds)
}

func runTCPSynTrace(
	sourceMac *net.HardwareAddr,
	sourceIP *net.IPAddr,
	targetMac *net.HardwareAddr,
	targetIP *net.IPAddr,
	livePacketSource *LivePacketSource,
	maxTTL uint8,
	disableIPPTRLookup bool,
	timeoutSeconds uint,
	port int) error {
	return runTrace(
		0,
		func(handle *pcap.Handle, ttl uint8) error {
			var linkLayer gopacket.SerializableLayer = nil
			if sourceMac != nil && targetMac != nil {
				linkLayer = &layers.Ethernet{
					SrcMAC:       *sourceMac,
					DstMAC:       *targetMac,
					EthernetType: layers.EthernetTypeIPv4,
				}
			}
			networkLayer := layers.IPv4{
				Version:  4,
				Id:       uint16(rand.Uint32()),
				Flags:    layers.IPv4DontFragment,
				TTL:      ttl,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    sourceIP.IP,
				DstIP:    targetIP.IP,
			}
			transportLayer := layers.TCP{
				SrcPort: layers.TCPPort(uint16(rand.Uint32())),
				DstPort: layers.TCPPort(port),
				Seq:     rand.Uint32(),
				Ack:     0,
				Window:  1450,
				SYN:     true,
			}
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, []byte{}); err != nil {
				return err
			}
			return nil
		},
		livePacketSource,
		maxTTL,
		disableIPPTRLookup,
		timeoutSeconds)
}

func runTrace(
	firstAckSeqNumber uint32,
	sendProbeFunc func(handle *pcap.Handle, ttl uint8) error,
	livePacketSource *LivePacketSource,
	maxTTL uint8,
	disableIPPTRLookup bool,
	timeoutSeconds uint) error {

	for ttl := uint8(1); ttl <= maxTTL; ttl++ {
		fmt.Printf("%d. ", ttl)

		var start = time.Now()

		if err := sendProbeFunc(livePacketSource.PcapHandle, ttl); err != nil {
			return err
		}

		var breakOuter = false
		for {
			var frame gopacket.Packet
			select {
			case frame = <-livePacketSource.PacketChan:
				break
			case <-time.After(time.Second * time.Duration(timeoutSeconds)):
				fmt.Printf("*\n")
				break
			}

			var elapsedTime = time.Since(start)

			if frame == nil {
				break
			}

			ipPacket := frame.NetworkLayer().(*layers.IPv4)
			tcpPacket, _ := frame.Layer(layers.LayerTypeTCP).(*layers.TCP)
			icmpPacket, _ := frame.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)

			if ipPacket == nil {
				return fmt.Errorf("Unexpected packet: %s", frame)
			}

			if tcpPacket != nil &&
				((tcpPacket.Seq == firstAckSeqNumber && !tcpPacket.FIN && !tcpPacket.RST) ||
					(tcpPacket.SYN && !tcpPacket.ACK)) {
				continue
			}

			var IPSourceDNSNameFragment = ""
			if !disableIPPTRLookup {
				IPSourceDNSNames, _ := net.LookupAddr(ipPacket.SrcIP.String())
				if IPSourceDNSNames == nil {
					IPSourceDNSNames = []string{}
				}
				if len(IPSourceDNSNames) > 0 {
					dnsName := strings.TrimRight(IPSourceDNSNames[0], ".")
					IPSourceDNSNameFragment = "(" + dnsName + ") "
				}
			}

			if tcpPacket != nil {
				var tcpFlag = "(unexpected flag)"
				if tcpPacket.ACK {
					if tcpPacket.SYN {
						tcpFlag = "SYN-ACK"
					} else if tcpPacket.FIN {
						tcpFlag = "FIN-ACK"
					} else if tcpPacket.RST {
						tcpFlag = "RST-ACK"
					} else {
						tcpFlag = "ACK"
					}
				} else if tcpPacket.RST {
					tcpFlag = "RST"
				}

				fmt.Printf("%s %s[TCP %s] %s\n", ipPacket.SrcIP, IPSourceDNSNameFragment, tcpFlag, elapsedTime)

				if tcpPacket.FIN {
					return errors.New("remote peer actively closed the connection")
				}

				breakOuter = true
				break
			}

			if icmpPacket != nil {
				fmt.Printf("%s %s%s\n", ipPacket.SrcIP, IPSourceDNSNameFragment, elapsedTime)
				break
			}
		}

		if breakOuter {
			break
		}
	}

	return nil
}

func sendRawPacket(
	pcapHandle *pcap.Handle,
	linkLayer gopacket.SerializableLayer,
	networkLayer layers.IPv4,
	transportLayer layers.TCP,
	tcpPayload []byte) error {

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if err := transportLayer.SetNetworkLayerForChecksum(&networkLayer); err != nil {
		return err
	}

	if linkLayer != nil {
		if err := gopacket.SerializeLayers(
			buffer,
			opts,
			linkLayer,
			&networkLayer,
			&transportLayer,
			gopacket.Payload(tcpPayload)); err != nil {
			return err
		}
		if err := pcapHandle.WritePacketData(buffer.Bytes()); err != nil {
			return err
		}

		return nil
	}

	conn, err := net.Dial("ip4:tcp", networkLayer.DstIP.String()+fmt.Sprintf("%d", transportLayer.DstPort))
	if err != nil {
		return err
	}
	ipConn := ipv4.NewConn(conn)
	if err := ipConn.SetTTL(int(networkLayer.TTL)); err != nil {
		return err
	}
	if err := gopacket.SerializeLayers(buffer, opts, &transportLayer, gopacket.Payload(tcpPayload)); err != nil {
		return err
	}
	if _, err = conn.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}
