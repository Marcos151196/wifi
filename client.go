package wifi

import (
	"fmt"
	"runtime"
)

var (
	// errUnimplemented is returned by all functions on platforms that
	// do not have package wifi implemented.
	errUnimplemented = fmt.Errorf("package wifi not implemented on %s/%s",
		runtime.GOOS, runtime.GOARCH)
)

// A Client is a type which can access WiFi device actions and statistics
// using operating system-specific operations.
type Client struct {
	c osClient
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Interfaces returns a list of the system's WiFi network interfaces.
func (c *Client) Interfaces() ([]*Interface, error) {
	return c.c.Interfaces()
}

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// StationInfo retrieves all station statistics about a WiFi interface.
func (c *Client) StationInfoDump(ifi *Interface) ([]*StationInfo, error) {
	return c.c.StationInfoDump(ifi)
}

func (c *Client) StationInfo(ifiName string, STAMAC string) (*StationInfo, error) {
	return c.c.StationInfo(ifiName, STAMAC)
}

func (c *Client) GetWiphy(ifi *Interface) (error) {
	return c.c.GetWiphy(ifi)
}

func (c *Client) SetTxPower(ifiName string, PowerSetting int, dBm uint16) (error) {
	return c.c.SetTxPower(ifiName, PowerSetting, dBm)
}

func (c *Client) SetPhyName(ifiName string, name string) (error) {
	return c.c.SetPhyName(ifiName,name)
}

func (c *Client) SetChannel(ifiName string, channel int, channelType int) (error) {
	return c.c.SetChannel(ifiName, channel, channelType)
}

func (c *Client) DelSTA(STAMAC string) (error) {
	return c.c.DelSTA(STAMAC)
}

func (c *Client) GetInterface(ifiName string) (*Interface, error){
	return c.c.GetInterface(ifiName)
}

func (c *Client) GetSTA(MAC string) (*StationInfo, error){
	return c.c.GetSTA(MAC)
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	Close() error
	Interfaces() ([]*Interface, error)
	BSS(ifi *Interface) (*BSS, error)
	StationInfoDump(ifi *Interface) ([]*StationInfo, error)
	StationInfo(ifiName string, STAMAC string) (*StationInfo, error)
	GetWiphy(ifi *Interface) (error)
	SetTxPower(ifiName string, PowerSetting int, dBm uint16) (error)
	SetPhyName(ifiName string, name string) (error)
	SetChannel(ifiName string, channel int, channelType int) (error) 
	DelSTA(STAMAC string) (error)
	GetInterface(ifiName string) (*Interface, error)
	GetSTA(MAC string) (*StationInfo, error)
}
