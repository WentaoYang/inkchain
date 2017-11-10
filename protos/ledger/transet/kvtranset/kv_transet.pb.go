// Code generated by protoc-gen-go. DO NOT EDIT.
// source: ledger/transet/kvtranset/kv_transet.proto

/*
Package kvtranset is a generated protocol buffer package.

It is generated from these files:
	ledger/transet/kvtranset/kv_transet.proto

It has these top-level messages:
	KVTranSet
	KVTrans
*/
package kvtranset

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type KVTranSet struct {
	Trans []*KVTrans `protobuf:"bytes,1,rep,name=trans" json:"trans,omitempty"`
}

func (m *KVTranSet) Reset()                    { *m = KVTranSet{} }
func (m *KVTranSet) String() string            { return proto.CompactTextString(m) }
func (*KVTranSet) ProtoMessage()               {}
func (*KVTranSet) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *KVTranSet) GetTrans() []*KVTrans {
	if m != nil {
		return m.Trans
	}
	return nil
}

type KVTrans struct {
	To          string `protobuf:"bytes,1,opt,name=to" json:"to,omitempty"`
	BalanceType string `protobuf:"bytes,2,opt,name=balance_type,json=balanceType" json:"balance_type,omitempty"`
	Amount      []byte `protobuf:"bytes,3,opt,name=amount,proto3" json:"amount,omitempty"`
}

func (m *KVTrans) Reset()                    { *m = KVTrans{} }
func (m *KVTrans) String() string            { return proto.CompactTextString(m) }
func (*KVTrans) ProtoMessage()               {}
func (*KVTrans) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *KVTrans) GetTo() string {
	if m != nil {
		return m.To
	}
	return ""
}

func (m *KVTrans) GetBalanceType() string {
	if m != nil {
		return m.BalanceType
	}
	return ""
}

func (m *KVTrans) GetAmount() []byte {
	if m != nil {
		return m.Amount
	}
	return nil
}

func init() {
	proto.RegisterType((*KVTranSet)(nil), "kvtranset.KVTranSet")
	proto.RegisterType((*KVTrans)(nil), "kvtranset.KVTrans")
}

func init() { proto.RegisterFile("ledger/transet/kvtranset/kv_transet.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 217 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0xb1, 0x6b, 0x84, 0x30,
	0x14, 0xc6, 0x89, 0x47, 0xaf, 0xf8, 0xee, 0xe8, 0x90, 0xa1, 0x64, 0xb4, 0x37, 0xa5, 0x4b, 0x02,
	0x2d, 0xb7, 0x75, 0xea, 0xda, 0xcd, 0x4a, 0x87, 0x2e, 0x47, 0xb4, 0x41, 0x45, 0x4d, 0x24, 0x3e,
	0x0b, 0xfe, 0xf7, 0x85, 0x24, 0xea, 0xd4, 0xed, 0x97, 0xef, 0xfd, 0x1e, 0x7c, 0x79, 0xf0, 0xdc,
	0xeb, 0x9f, 0x5a, 0x3b, 0x89, 0x4e, 0x99, 0x49, 0xa3, 0xec, 0x7e, 0x77, 0xba, 0x45, 0x14, 0xa3,
	0xb3, 0x68, 0x69, 0xba, 0xcd, 0x2e, 0x57, 0x48, 0x3f, 0xbe, 0x0a, 0xa7, 0xcc, 0xa7, 0x46, 0xca,
	0xe1, 0xce, 0xe7, 0x8c, 0x64, 0x07, 0x7e, 0x7a, 0xa1, 0x62, 0xf3, 0x44, 0x90, 0xa6, 0x3c, 0x08,
	0x97, 0x02, 0xee, 0x63, 0x42, 0x1f, 0x20, 0x41, 0xcb, 0x48, 0x46, 0x78, 0x9a, 0x27, 0x68, 0xe9,
	0x13, 0x9c, 0x4b, 0xd5, 0x2b, 0x53, 0xe9, 0x1b, 0x2e, 0xa3, 0x66, 0x89, 0x9f, 0x9c, 0x62, 0x56,
	0x2c, 0xa3, 0xa6, 0x8f, 0x70, 0x54, 0x83, 0x9d, 0x0d, 0xb2, 0x43, 0x46, 0xf8, 0x39, 0x8f, 0xaf,
	0xf7, 0x19, 0xae, 0xd6, 0xd5, 0xa2, 0x35, 0x5d, 0xd5, 0xa8, 0xd6, 0xec, 0xe0, 0x6b, 0x4f, 0x22,
	0xfc, 0x50, 0xac, 0x9d, 0xb6, 0x76, 0xdf, 0x6f, 0x75, 0x8b, 0xcd, 0x5c, 0x8a, 0xca, 0x0e, 0x72,
	0x5d, 0xda, 0x21, 0x6c, 0xcb, 0xff, 0xee, 0x53, 0x1e, 0xbd, 0xf0, 0xfa, 0x17, 0x00, 0x00, 0xff,
	0xff, 0x54, 0x75, 0x28, 0x58, 0x42, 0x01, 0x00, 0x00,
}