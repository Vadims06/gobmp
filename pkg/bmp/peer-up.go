package bmp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/tools"
)

// PeerUpMessage defines BMPPeerUpMessage per rfc7854
type PeerUpMessage struct {
	LocalAddress     []byte
	LocalPort        uint16
	RemotePort       uint16
	SentOpen         *bgp.OpenMessage
	ReceivedOpen     *bgp.OpenMessage
	Information      []InformationalTLV
	isRemotePeerIPv6 bool
}

// GetLocalAddressString returns the local address as a string, properly formatted as IPv4 or IPv6 based on the isRemotePeerIPv6 flag.
func (pum *PeerUpMessage) GetLocalAddressString() string {
	if pum.isRemotePeerIPv6 {
		return net.IP(pum.LocalAddress).To16().String()
	}
	return net.IP(pum.LocalAddress[12:]).To4().String()
}

// GetVRFTableName returns the VRF table name from the Peer Up message's Informational TLVs, if present.
func (pum *PeerUpMessage) GetVRFTableName() (string, bool) {
	for _, tlv := range pum.Information {
		if tlv.InformationType != PeerUpTLVVRFTableName {
			continue
		}
		return string(tlv.Information), true
	}
	return "", false
}

// GetAdminLabel returns the administrative label from the Peer Up message's Informational TLVs, if present.
func (pum *PeerUpMessage) GetAdminLabel() (string, bool) {
	for _, tlv := range pum.Information {
		if tlv.InformationType != PeerUpTLVAdminLabel {
			continue
		}
		return string(tlv.Information), true
	}
	return "", false
}

// UnmarshalPeerUpMessage processes Peer Up message and returns BMPPeerUpMessage object
func UnmarshalPeerUpMessage(b []byte, isIPv6 bool) (*PeerUpMessage, error) {
	if glog.V(6) {
		glog.Infof("BMP Peer Up Message Raw: %s", tools.MessageHex(b))
	}
	var err error
	pu := &PeerUpMessage{
		LocalAddress:     make([]byte, 16),
		SentOpen:         &bgp.OpenMessage{},
		ReceivedOpen:     &bgp.OpenMessage{},
		Information:      make([]InformationalTLV, 0),
		isRemotePeerIPv6: isIPv6,
	}
	p := 0
	if p+16 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Local Address, need 16 bytes, have %d", len(b)-p)
	}
	copy(pu.LocalAddress, b[:16])
	p += 16
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Local Port, need 2 bytes, have %d", len(b)-p)
	}
	pu.LocalPort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Peer Up message Remote Port, need 2 bytes, have %d", len(b)-p)
	}
	pu.RemotePort = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	// Processing Sent Open and Received Open messages.
	var l int
	if pu.SentOpen, l, err = unmarshalPeerUpOpen(b[p:], "Sent"); err != nil {
		return nil, err
	}
	p += l
	if pu.ReceivedOpen, l, err = unmarshalPeerUpOpen(b[p:], "Received"); err != nil {
		return nil, err
	}
	p += l
	// Last part is optional Informational TLVs
	if len(b) > int(p) {
		// Since pointer p does not point to the end of buffer,
		// then processing Informational TLVs
		tlvs, err := UnmarshalTLV(b[p:])
		if err != nil {
			return nil, err
		}
		pu.Information = tlvs
	}
	return pu, nil
}

// bgpHeaderLength is a BGP message with no body: marker, length and type.
const bgpHeaderLength = 19

// unmarshalPeerUpOpen reads one OPEN of a Peer Up and returns it with the bytes it took.
// FRR sends a header-only OPEN when it saved none for the peer; the session is still real,
// so the OPEN is returned empty with an unset BGP Identifier instead of rejecting the Peer Up.
func unmarshalPeerUpOpen(b []byte, direction string) (*bgp.OpenMessage, int, error) {
	if len(b) < bgpHeaderLength {
		return nil, 0, fmt.Errorf("not enough bytes to unmarshal Peer Up message %s Open message, need at least %d bytes, have %d", direction, bgpHeaderLength, len(b))
	}
	// Getting actual length which is located right after BGP marker (16 bytes)
	l := int(binary.BigEndian.Uint16(b[bgp.BGPMessageMarkerLength : bgp.BGPMessageMarkerLength+2]))
	if l == bgpHeaderLength && b[bgpHeaderLength-1] == 1 {
		return &bgp.OpenMessage{Length: bgpHeaderLength, Type: 1, BGPID: make([]byte, 4), Capabilities: bgp.Capability{}}, l, nil
	}
	if l < bgp.BGPMinOpenMessageLength {
		return nil, 0, fmt.Errorf("invalid BGP Open message length %d, less than minimum %d bytes", l, bgp.BGPMinOpenMessageLength)
	}
	if l > len(b) {
		return nil, 0, fmt.Errorf("not enough bytes to unmarshal Peer Up message %s Open message, need %d bytes, have %d", direction, l, len(b))
	}
	open, err := bgp.UnmarshalBGPOpenMessage(b[bgp.BGPMessageMarkerLength:l])
	if err != nil {
		return nil, 0, err
	}
	return open, l, nil
}
