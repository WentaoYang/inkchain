// Code generated by protoc-gen-go. DO NOT EDIT.
// source: peer/configuration.proto

package peer

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// AnchorPeers simply represents list of anchor peers which is used in ConfigurationItem
type AnchorPeers struct {
	AnchorPeers []*AnchorPeer `protobuf:"bytes,1,rep,name=anchor_peers,json=anchorPeers" json:"anchor_peers,omitempty"`
}

func (m *AnchorPeers) Reset()                    { *m = AnchorPeers{} }
func (m *AnchorPeers) String() string            { return proto.CompactTextString(m) }
func (*AnchorPeers) ProtoMessage()               {}
func (*AnchorPeers) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{0} }

func (m *AnchorPeers) GetAnchorPeers() []*AnchorPeer {
	if m != nil {
		return m.AnchorPeers
	}
	return nil
}

// AnchorPeer message structure which provides information about anchor peer, it includes host name,
// port number and peer certificate.
type AnchorPeer struct {
	// DNS host name of the anchor peer
	Host string `protobuf:"bytes,1,opt,name=host" json:"host,omitempty"`
	// The port number
	Port int32 `protobuf:"varint,2,opt,name=port" json:"port,omitempty"`
}

func (m *AnchorPeer) Reset()                    { *m = AnchorPeer{} }
func (m *AnchorPeer) String() string            { return proto.CompactTextString(m) }
func (*AnchorPeer) ProtoMessage()               {}
func (*AnchorPeer) Descriptor() ([]byte, []int) { return fileDescriptor4, []int{1} }

func (m *AnchorPeer) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *AnchorPeer) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func init() {
	proto.RegisterType((*AnchorPeers)(nil), "protos.AnchorPeers")
	proto.RegisterType((*AnchorPeer)(nil), "protos.AnchorPeer")
}

func init() { proto.RegisterFile("peer/configuration.proto", fileDescriptor4) }

var fileDescriptor4 = []byte{
	// 182 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x8f, 0x3f, 0xcf, 0xc2, 0x20,
	0x10, 0x87, 0xc3, 0xfb, 0xaa, 0x89, 0xd4, 0x89, 0x89, 0xb1, 0x76, 0x62, 0xa2, 0x89, 0x7f, 0x3e,
	0x80, 0xc6, 0xd5, 0xc4, 0x74, 0x74, 0x31, 0x94, 0x60, 0x21, 0x46, 0xae, 0x39, 0xe8, 0xf7, 0x37,
	0x50, 0x0d, 0x13, 0x0f, 0x77, 0xcf, 0x2f, 0x77, 0x47, 0xf9, 0x68, 0x0c, 0xb6, 0x1a, 0xfc, 0xd3,
	0x0d, 0x13, 0xaa, 0xe8, 0xc0, 0xcb, 0x11, 0x21, 0x02, 0x5b, 0xe5, 0x27, 0x34, 0x17, 0x5a, 0x9d,
	0xbc, 0xb6, 0x80, 0x37, 0x63, 0x30, 0xb0, 0x23, 0xdd, 0xa8, 0xfc, 0x7d, 0xa4, 0x64, 0xe0, 0xa4,
	0xfe, 0x17, 0xd5, 0x8e, 0xcd, 0xa1, 0x20, 0x8b, 0xda, 0x55, 0xaa, 0xc4, 0x9a, 0x03, 0xa5, 0xa5,
	0xc5, 0x18, 0x5d, 0x58, 0x08, 0x91, 0x93, 0x9a, 0x88, 0x75, 0x97, 0x39, 0xd5, 0x46, 0xc0, 0xc8,
	0xff, 0x6a, 0x22, 0x96, 0x5d, 0xe6, 0xf3, 0x95, 0x6e, 0x01, 0x07, 0xe9, 0xfc, 0x4b, 0x5b, 0xe5,
	0x7c, 0x81, 0xef, 0xb4, 0xb4, 0xc2, 0x5d, 0x0c, 0x2e, 0xda, 0xa9, 0x97, 0x1a, 0xde, 0xed, 0x4f,
	0x28, 0x30, 0x9b, 0x6d, 0x32, 0xfb, 0xf9, 0xa4, 0xfd, 0x27, 0x00, 0x00, 0xff, 0xff, 0xcb, 0x3d,
	0x79, 0xa9, 0xf5, 0x00, 0x00, 0x00,
}