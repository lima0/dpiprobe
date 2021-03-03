package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/refraction-networking/utls"
	"golang.org/x/net/ipv4"
)

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

func runClientHelloTrace(
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

	fmt.Println("Running in HTTPS ClientHello mode")
	// use uTLS library to create a google chrome fingerprinted ClientHello using empty connection
	var conn net.Conn = nil
	uTLSConn := tls.UClient(conn, &tls.Config{ServerName: domain}, tls.HelloChrome_Auto)
	var err = uTLSConn.BuildHandshakeState()
	if err != nil {
		return err
	}
	rawClientHello := uTLSConn.HandshakeState.Hello.Raw
	recordHeader := []byte{0x16, 0x03, 0x01}
	recordHeaderBytes := make([]byte, 2)
	clientHelloUInt16 := uint16(len(rawClientHello))
	binary.BigEndian.PutUint16(recordHeaderBytes, clientHelloUInt16)
	fullClientHello := append(recordHeader, recordHeaderBytes...)
	fullClientHello = append(fullClientHello, rawClientHello...) // append record header + ClientHello size to payload

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
			if err := sendRawPacket(handle, linkLayer, networkLayer, transportLayer, fullClientHello); err != nil {
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
