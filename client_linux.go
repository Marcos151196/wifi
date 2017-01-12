//+build linux

package wifi

import (
	"errors"
	"math"
	"net"
	"os"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/genetlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wifi/internal/nl80211"
)

// Errors which may occur when interacting with generic netlink.
var (
	errMultipleMessages     = errors.New("expected only one generic netlink message")
	errInvalidCommand       = errors.New("invalid generic netlink response command")
	errInvalidFamilyVersion = errors.New("invalid generic netlink response family version")
)

var _ osClient = &client{}

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c             genl
	familyID      uint16
	familyVersion uint8
}

// genl is an interface over generic netlink, so netlink interactions can
// be stubbed in tests.
type genl interface {
	Close() error
	GetFamily(name string) (genetlink.Family, error)
	Execute(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error)
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	g := &sysGENL{Conn: c}
	return initClient(g)
}

// initClient is the internal constructor for a client, used in tests.
func initClient(c genl) (*client, error) {
	family, err := c.GetFamily(nl80211.GenlName)
	if err != nil {
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

	return parseInterfaces(msgs)
}

// StationInfo requests that nl80211 return station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) (*StationInfo, error) {
	b, err := netlink.MarshalAttributes(ifi.stationInfoAttrs())
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

	if len(msgs) > 1 {
		return nil, errMultipleMessages
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewStation); err != nil {
		return nil, err
	}

	return parseStationInfo(msgs[0].Data)
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
func parseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	return ifis, nil
}

// stationInfoAttrs returns the netlink attributes required from an Interface
// to retrieve a StationInfo.
func (ifi *Interface) stationInfoAttrs() []netlink.Attribute {
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
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
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
		case nl80211.AttrIftype:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case nl80211.AttrWdev:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case nl80211.AttrWiphyFreq:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	for _, a := range attrs {
		// The other attributes that are returned here appear to indicate the
		// interface index and MAC address, which is information we already
		// possess.  No need to parse them for now.
		if a.Type != nl80211.AttrStaInfo {
			continue
		}

		nattrs, err := netlink.UnmarshalAttributes(a.Data)
		if err != nil {
			return nil, err
		}

		var info StationInfo
		if err := (&info).parseAttributes(nattrs); err != nil {
			return nil, err
		}

		return &info, nil
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.StaInfoConnectedTime:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case nl80211.StaInfoInactiveTime:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.StaInfoRxBytes64:
			info.ReceivedBytes = nlenc.Uint64(a.Data)
		case nl80211.StaInfoTxBytes64:
			info.TransmittedBytes = nlenc.Uint64(a.Data)
		case nl80211.StaInfoSignal:
			// Converted into the typical negative strength format
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			info.Signal = int(a.Data[0]) - math.MaxUint8
		case nl80211.StaInfoRxPackets:
			info.ReceivedPackets = nlenc.Uint32(a.Data)
		case nl80211.StaInfoTxPackets:
			info.TransmittedPackets = nlenc.Uint32(a.Data)
		case nl80211.StaInfoTxRetries:
			info.TransmitRetries = nlenc.Uint32(a.Data)
		case nl80211.StaInfoTxFailed:
			info.TransmitFailed = nlenc.Uint32(a.Data)
		case nl80211.StaInfoBeaconLoss:
			info.BeaconLoss = nlenc.Uint32(a.Data)
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
			case nl80211.StaInfoTxBitrate:
				info.TransmitBitrate = rate.Bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == nl80211.StaInfoRxBytes {
			info.ReceivedBytes = uint64(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == nl80211.StaInfoTxBytes {
			info.TransmittedBytes = uint64(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// rateInfo provides statistics about the receive or transmit rate of
// an interface.
type rateInfo struct {
	// Bitrate in bits per second.
	Bitrate int
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

var _ genl = &sysGENL{}

// sysGENL is the system implementation of genl, using generic netlink.
type sysGENL struct {
	*genetlink.Conn
}

// GetFamily is a small adapter to make *genetlink.Conn implement genl.
func (g *sysGENL) GetFamily(name string) (genetlink.Family, error) {
	return g.Conn.Family.Get(name)
}