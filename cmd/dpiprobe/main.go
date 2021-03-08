package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/idna"
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
		fmt.Printf("Invalid mode (%s) \nRun \"dpiprobe --help\" for usage instructions.\n", *connectionMode)
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
		err = runClientHelloTrace(
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
