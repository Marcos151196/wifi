//+build linux

package wifi

import (
	"bytes"
	"errors"
	"net"
	"os"
	"time"
	"unicode/utf8"
	"strings"
	"fmt"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/Marcos151196/wifi/nl80211"
)

// Errors which may occur when interacting with generic netlink.
var (
	errInvalidCommand       = errors.New("invalid generic netlink response command")
	errInvalidFamilyVersion = errors.New("invalid generic netlink response family version")
)

var _ osClient = &client{}

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             *genetlink.Conn
	familyID      uint16
	familyVersion uint8
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	return initClient(c)
}

func initClient(c *genetlink.Conn) (*client, error) {
	family, err := c.GetFamily(nl80211.GenlName)
	if err != nil {
		// Ensure the genl socket is closed on error to avoid leaking file
		// descriptors.
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:             c,
		familyID:      family.ID,
		familyVersion: family.Version,
	}, nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error {
	return c.c.Close()
}

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetInterface,
			Version: c.familyVersion,
		},
	}
	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewInterface); err != nil {
		return nil, err
	}
	ifis,err := c.parseInterfaces(msgs)

	return ifis,err
}


// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve BSS information for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetScan,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

// StationInfo requests that nl80211 return all station info for the specified
// Interface.
func (c *client) StationInfoDump(ifi *Interface) ([]*StationInfo, error) {
	if (ifi == nil){
		return nil, errors.New("Interface does not exist.")
	}
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve station info for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			// From nl80211.h:
			//  * @NL80211_CMD_GET_STATION: Get station attributes for station identified by
			//  * %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.
			Command: nl80211.CmdGetStation,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {

		return nil, err
	}

	if len(msgs) == 0 {
		return nil, os.ErrNotExist
	}

	stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		if err := c.checkMessages(msgs, nl80211.CmdNewStation); err != nil {
			return nil, err
		}

		if stations[i], err = ifi.parseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return stations, nil
}


//////////GETS ONE STATION INFO SPECIFIED BY MAC /////
func (c *client) StationInfo(ifiMAC string, STAMAC string) (*StationInfo, error) {
	var station *StationInfo
	ifi,err := c.GetInterface(ifiMAC)
	if (ifi == nil){
		return nil, errors.New("Interface does not exist.")
	}
	MAC,_ := net.ParseMAC(STAMAC)
	attrs := []netlink.Attribute{
		{
			Length: 8,
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Length: 10,
			Type: nl80211.AttrMac,
			Data: MAC,
		},
	}
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve station info for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			// From nl80211.h:
			//  * @NL80211_CMD_GET_STATION: Get station attributes for station identified by
			//  * %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.
			Command: nl80211.CmdGetStation,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if len(msgs) == 0 {
		return nil, os.ErrNotExist
	}

	for i := range msgs {
		if err := c.checkMessages(msgs, nl80211.CmdNewStation); err != nil {
			return nil, err
		}

		if station, err = ifi.parseStationInfo(msgs[i].Data); err != nil {
			return nil, err
		}
	}

	return station, nil
}






///////GET WIPHY INFO///////////
func (c *client) GetWiphy(ifi *Interface) (error) {

	attrs := []netlink.Attribute{
		{
			Length: 8,
			Type: nl80211.AttrWiphy,
			Data: nlenc.Uint32Bytes(uint32(ifi.PHY)),
		},
	}
	b, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return err
	}

	// Ask nl80211 to retrieve station info for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetWiphy,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge | netlink.HeaderFlagsRoot | netlink.HeaderFlagsMatch
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return err
	}

	if len(msgs) == 0 {
		return os.ErrNotExist
	}

	//fmt.Printf("\nAQUI: %v\n", msgs)

	// Wiphys := make([]*StationInfo, len(msgs))
	// stations := make([]*StationInfo, len(msgs))
	for i := range msgs {
		//fmt.Printf("%v\t",msgs[i].Data)´

		if err := c.checkMessages(msgs, nl80211.CmdNewWiphy); err != nil {
			return err
		}

		err = ifi.parseWiphyInfo(msgs[i].Data)
		if (err != nil){
			return err
		}
	}

	// return stations, nil
	return nil
}



///////SET TX POWER///////////
func (c *client) SetTxPower(ifiMAC string, PowerSetting int, dBm uint16) (error) {
	ifi,err := c.GetInterface(ifiMAC)
	if(err != nil){
		return err
	}
	PowerLevel := nlenc.Uint16Bytes(uint16(dBm*100))
	attrs := []netlink.Attribute{
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: nl80211.AttrWiphyTxPowerSetting,
			Data: nlenc.Uint32Bytes(uint32(PowerSetting)),
		},
		{
			Length: 8,
			Type: nl80211.AttrWiphyTxPowerLevel,
			Data: PowerLevel,
		},
	}
	b,_ := netlink.MarshalAttributes(attrs)
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdSetWiphy,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return err
	}

	if len(msgs) == 0 {
		return os.ErrNotExist
	}

	return nil
}

///////SET WIPHY NAME///////////
func (c *client) SetPhyName(ifiMAC string, name string) (error) {
	ifi,err := c.GetInterface(ifiMAC)
	if(err != nil){
		return err
	}
	NewName := []byte(name)
	attrs := []netlink.Attribute{
		{
			Type: nl80211.AttrWiphy,
			Data: nlenc.Uint32Bytes(uint32(ifi.PHY)),
		},
		{
			Length: uint16(len(NewName)+5), //Length = length(1 byte) + padding(1 byte) + type(1 byte) + padding(1 byte) + payload(x bytes) + padding(1 byte) = 1+1+1+1+length(Data)+1
			Type: nl80211.AttrWiphyName,
			Data: NewName,
		},
	}
	b,_ := netlink.MarshalAttributes(attrs)
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdSetWiphy,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return err
	}

	if len(msgs) == 0 {
		return os.ErrNotExist
	}

	return nil
}

///////SET Channel///////////
func (c *client) SetChannel(ifiMAC string, channel int, channelType int) (error) {
	ifi,err := c.GetInterface(ifiMAC)
	if(err != nil){
		return err
	}

	attrs := []netlink.Attribute{
		{
			Length: 8,
			Type: nl80211.AttrWiphy,
			Data: nlenc.Uint32Bytes(uint32(ifi.PHY)),
		},
		{
			Length: 8,
			Type: nl80211.AttrWiphyFreq,
			Data: nlenc.Uint32Bytes(uint32(ChannelToFreq(channel))),
		},
		{
			Length: 8,
			Type: nl80211.AttrWiphyChannelType,
			Data: nlenc.Uint32Bytes(uint32(channelType)),
		},
	}
	b,_ := netlink.MarshalAttributes(attrs)
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdSetWiphy,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return err
	}

	if len(msgs) == 0 {
		return os.ErrNotExist
	}

	return nil
}

///////DELETE STATION///////////
func (c *client) DelSTA(STAMAC string) (error) {

	sta,err := c.GetSTA(STAMAC)
	if(err != nil){
		return errors.New("Specified STA does not exist.")
	}
	MAC,_ := net.ParseMAC(STAMAC)
	attrs := []netlink.Attribute{
		{
			Length: 8,
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(sta.InterfaceIndex)),
		},
		{
			Length: 10,
			Type: nl80211.AttrMac,
			Data: MAC,
		},
	}
	b,_ := netlink.MarshalAttributes(attrs)
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdDelStation,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsAcknowledge
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return err
	}

	if err := c.checkMessages(msgs, nl80211.CmdDelStation); err != nil {
		return err
	}
	
	return nil
}

///////////////GET INTERFACE///////////////////
func (c *client) GetInterface(MAC string) (*Interface, error){
	interfaces,err := c.Interfaces()
	if(err != nil){
		return nil, errors.New("Error when trying to get the interface list.")
	}
	for _,ifi := range interfaces{
		if(strings.Compare(ifi.HardwareAddr.String(), MAC) == 0){
			return ifi,nil
		}
	}
	return nil, errors.New("Interface does not exist.")
}

///////////////GET STA///////////////////
func (c *client) GetSTA(STAMAC string) (*StationInfo, error){
	interfaces,err := c.Interfaces()
	if(err != nil){
		return nil, errors.New("Error when trying to get the interface list.")
	}
	for _,ifi := range interfaces{
		for _,sta := range ifi.STAList{
			if(strings.Compare(sta, STAMAC) == 0){
				return c.StationInfo(ifi.HardwareAddr.String(), STAMAC)
			}
		}
	}
	return nil, errors.New("Interface does not exist.")
}


// checkMessages verifies that response messages from generic netlink contain
// the command and family version we expect.
func (c *client) checkMessages(msgs []genetlink.Message, command uint8) error {
	for _, m := range msgs {
		if m.Header.Command != command {
			return errInvalidCommand
		}

		if m.Header.Version != c.familyVersion {
			return errInvalidFamilyVersion
		}
	}

	return nil
}

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func (c *client) parseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))

	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs,c); err != nil {
			return nil, err
		}

		if err := c.GetWiphy(&ifi); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	

	return ifis, nil
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: nl80211.AttrMac,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute, c *client) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrIfindex:
			ifi.Index = int(nlenc.Uint32(a.Data))
		case nl80211.AttrIfname:
			ifi.Name = nlenc.String(a.Data)
		case nl80211.AttrMac:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case nl80211.AttrWiphy:
			ifi.PHY = int(nlenc.Uint32(a.Data))
		case nl80211.AttrWiphyName:
			ifi.PHYName = nlenc.String(a.Data)
		case nl80211.AttrIftype:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case nl80211.AttrWdev:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case nl80211.AttrWiphyFreq:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
			ifi.Channel = FreqToChannel(int(nlenc.Uint32(a.Data)))
		case nl80211.AttrWiphyTxPowerLevel:
			ifi.TxPower =  float32(nlenc.Uint32(a.Data)/100)
		case nl80211.AttrSsid:
			ifi.SSID =  nlenc.String(a.Data)
		case nl80211.AttrWiphyChannelType:
			ifi.ChannelType = int(nlenc.Uint32(a.Data))
		case nl80211.AttrChannelWidth:

			switch int(nlenc.Uint32(a.Data)){
			case nl80211.ChanWidth20Noht:
				ifi.ChanWidth =  "20 MHz (No HT)"
			case nl80211.ChanWidth20:
				ifi.ChanWidth =  "20 MHz"
			case nl80211.ChanWidth40:
				ifi.ChanWidth =  "40 MHz"
			case nl80211.ChanWidth80:
				ifi.ChanWidth =  "80 MHz"
			case nl80211.ChanWidth80p80:
				ifi.ChanWidth =  "80+80 MHz"
			case nl80211.ChanWidth160:
				ifi.ChanWidth =  "160 MHz"
			case nl80211.ChanWidth5:
				ifi.ChanWidth =  "5 MHz"
			case nl80211.ChanWidth10:
				ifi.ChanWidth =  "10 MHz"
			}
		case nl80211.AttrCenterFreq1:
			ifi.CenterFreq1 = int(nlenc.Uint32(a.Data))
		case nl80211.AttrCenterFreq2:
			ifi.CenterFreq2 = int(nlenc.Uint32(a.Data))
			
		}
		stas,_ := c.StationInfoDump(ifi)
		STAarray := make([]string, len(stas))
		for i,sta := range stas{
			STAarray[i] = sta.HardwareAddr.String()
		}
		ifi.STAList = STAarray
	}

	return nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			if a.Type != nl80211.AttrBss {
				continue
			}

			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			// The BSS which is associated with an interface will have a status
			// attribute
			if !attrsContain(nattrs, nl80211.BssStatus) {
				continue
			}

			var bss BSS
			if err := (&bss).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			return &bss, nil
		}
	}

	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.BssBssid:
			b.BSSID = net.HardwareAddr(a.Data)
		case nl80211.BssFrequency:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case nl80211.BssBeaconInterval:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case nl80211.BssSeenMsAgo:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.BssStatus:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case nl80211.BssInformationElements:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				}
			}
		}
	}

	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func (ifi *Interface) parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}
	

	var info StationInfo
	info.Interface = ifi.HardwareAddr
	info.InterfaceIndex = ifi.Index
	for _, a := range attrs {
		//fmt.Printf("%v\n", a.Data)

		switch a.Type {
		case nl80211.AttrMac:
			info.HardwareAddr = net.HardwareAddr(a.Data)

		case nl80211.AttrStaInfo:
			nattrs, err := netlink.UnmarshalAttributes(a.Data)
			if err != nil {
				return nil, err
			}

			if err := (&info).parseAttributes(nattrs); err != nil {
				return nil, err
			}

			// nl80211.AttrStaInfo is last attibute we are interested in
			return &info, nil

			
		default:
			// The other attributes that are returned here appear
			// nl80211.AttrIfindex, nl80211.AttrGeneration
			// No need to parse them for now.
			continue
		}
	}

	// No station info found
	return nil, os.ErrNotExist
}

////////////PARSEWIPHYINFO
func (ifi *Interface) parseWiphyInfo(b []byte) (error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return err
	}
	// fmt.Printf("lol %v\n\n\n", attrs)
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrWiphyName:
			ifi.PHYName = nlenc.String(a.Data)
		default:
			continue
		}
	}
	// No station info found
	return nil
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		//fmt.Printf("%v\t",a.Type)
		switch a.Type {
		case nl80211.StaInfoConnectedTime:
			info.Connected = (time.Duration(nlenc.Uint32(a.Data)) * time.Second).Seconds()
		case nl80211.StaInfoInactiveTime:
			info.Inactive = (time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond).Seconds()
		case nl80211.StaInfoRxBytes64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoTxBytes64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoLlid:
			info.LLID = int(nlenc.Uint16(a.Data))
		case nl80211.StaInfoPlid:
			info.PLID = int(nlenc.Uint16(a.Data))
		case nl80211.StaInfoPlinkState:
			switch (int(nlenc.Uint8(a.Data))) {
			case nl80211.PlinkListen:
				info.PlinkState = "LISTEN"
			case nl80211.PlinkOpnSnt:
				info.PlinkState = "OPN_SNT"
			case nl80211.PlinkOpnRcvd:
				info.PlinkState = "OPN_RCVD"
			case nl80211.PlinkCnfRcvd:
				info.PlinkState = "CNF_RCVD"
			case nl80211.PlinkEstab:
				info.PlinkState = "ESTAB"
			case nl80211.PlinkHolding:
				info.PlinkState = "HOLDING"
			case nl80211.PlinkBlocked:
				info.PlinkState = "BLOCKED"
			default:
				info.PlinkState = "UNKNOWN"
			}
		case nl80211.StaInfoSignal:
			info.Signal = int(int8(a.Data[0]))
		case nl80211.StaInfoChainSignal:
			info.SignalH = int(int8(a.Data[4]))
			info.SignalV = int(int8(a.Data[12]))
		case nl80211.StaInfoSignalAvg:
			info.SignalAvg = int(int8(a.Data[0]))
		case nl80211.StaInfoChainSignalAvg:
			info.SignalAvgH = int(int8(a.Data[4]))
			info.SignalAvgV = int(int8(a.Data[12]))
		case nl80211.StaInfoStaFlags: 
			if(a.Data[0] & (2 << (nl80211.StaFlagAuthorized-1)) !=0 ){
				if(a.Data[4] & (2 << (nl80211.StaFlagAuthorized-1)) !=0 ){
					info.Authorized = 1
				} else{
					info.Authorized = 0
				}
			}

			if(a.Data[0] & (2 << (nl80211.StaFlagAuthenticated-1)) !=0 ){
				if(a.Data[4] & (2 << (nl80211.StaFlagAuthenticated-1)) !=0 ){
					info.Authenticated = 1
				} else{
					info.Authenticated = 0
				}
			}

			if(a.Data[0] & (2 << (nl80211.StaFlagAssociated-1)) !=0 ){
				if(a.Data[4] & (2 << (nl80211.StaFlagAssociated-1)) !=0 ){
					info.Associated = 1
				} else{
					info.Associated = 0
				}
			}
			
		case nl80211.StaInfoRxPackets:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxPackets:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxRetries:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxFailed:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoBeaconLoss:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoRxBitrate, nl80211.StaInfoTxBitrate:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case nl80211.StaInfoRxBitrate:
				info.ReceiveBitrate = rate.Bitrate
				info.ReceiveMCS = rate.MCS
			case nl80211.StaInfoTxBitrate:
				info.TransmitBitrate = rate.Bitrate
				info.TransmitMCS = rate.MCS
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == nl80211.StaInfoRxBytes {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == nl80211.StaInfoTxBytes {
			info.TransmittedBytes = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// rateInfo provides statistics about the receive or transmit rate of
// an interface.
type rateInfo struct {
	// Bitrate in bits per second.
	Bitrate int
	MCS string
}

// parseRateInfo parses a rateInfo from netlink attributes.
func parseRateInfo(b []byte) (*rateInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info rateInfo
	for _, a := range attrs {
		switch a.Type {
		case nl80211.RateInfoBitrate32:
			info.Bitrate = int(nlenc.Uint32(a.Data))
		case nl80211.RateInfoMcs:
			info.MCS = fmt.Sprintf("MCS %v", int(nlenc.Uint8(a.Data)))
		case nl80211.RateInfoVhtMcs:
			info.MCS = fmt.Sprintf("VHT-MCS %v", int(nlenc.Uint8(a.Data)))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.Bitrate == 0 && a.Type == nl80211.RateInfoBitrate {
			info.Bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	info.Bitrate *= 100 * 1000

	return &info, nil
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}

	return false
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}
