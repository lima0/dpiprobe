package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

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
