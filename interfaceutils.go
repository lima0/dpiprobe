package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// FindPcapInterfaceName Finds interface name for packet capture using an IP address
func FindPcapInterfaceName(ipAddress net.IP) (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	for _, networkInterface := range devices {
		interfaceAddresses := networkInterface.Addresses
		for _, interfaceAddress := range interfaceAddresses {
			interfaceIP := interfaceAddress.IP
			if interfaceIP.Equal(ipAddress) {
				return networkInterface.Name, nil
			}
		}
	}

	return "", nil
}

// findOutgoingPcapInterfaceNameAndIp Finds outgoing interface name and IP for packet capture
func findOutgoingPcapInterfaceNameAndIP(targetIP *net.IPAddr) (string, *net.IPAddr, error) {
	initialConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: targetIP.IP, Port: 443})
	if err != nil {
		return "", nil, err
	}

	localInterfaceIP := initialConn.LocalAddr().(*net.UDPAddr).IP
	_ = initialConn.Close()

	outgoingPcapInterfaceName, err := FindPcapInterfaceName(localInterfaceIP)
	if err != nil {
		return "", nil, err
	}
	if outgoingPcapInterfaceName == "" {
		return "", nil, fmt.Errorf("Unable to lookup the outgoing interface for local IP: %s", localInterfaceIP)
	}

	_, localNet, _ := net.ParseCIDR("127.0.0.0/8")
	if localNet.Contains(localInterfaceIP) {
		return "", nil, errors.New(
			"Outgoing interface is local. Either the destination is the local machine or a" +
				" local proxy is being used.\nPlease choose a remote destination or exclude this app from being" +
				" proxied and try again.")
	}

	return outgoingPcapInterfaceName, &net.IPAddr{IP: localInterfaceIP}, nil
}
