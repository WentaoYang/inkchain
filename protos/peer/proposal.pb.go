// Code generated by protoc-gen-go. DO NOT EDIT.
// source: peer/proposal.proto

package peer

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This structure is necessary to sign the proposal which contains the header
// and the payload. Without this structure, we would have to concatenate the
// header and the payload to verify the signature, which could be expensive
// with large payload
//
// When an endorser receives a SignedProposal message, it should verify the
// signature over the proposal bytes. This verification requires the following
// steps:
// 1. Verification of the validity of the certificate that was used to produce
//    the signature.  The certificate will be available once proposalBytes has
//    been unmarshalled to a Proposal message, and Proposal.header has been
//    unmarshalled to a Header message. While this unmarshalling-before-verifying
//    might not be ideal, it is unavoidable because i) the signature needs to also
//    protect the signing certificate; ii) it is desirable that Header is created
//    once by the client and never changed (for the sake of accountability and
//    non-repudiation). Note also that it is actually impossible to conclusively
//    verify the validity of the certificate included in a Proposal, because the
//    proposal needs to first be endorsed and ordered with respect to certificate
//    expiration transactions. Still, it is useful to pre-filter expired
//    certificates at this stage.
// 2. Verification that the certificate is trusted (signed by a trusted CA) and
//    that it is allowed to transact with us (with respect to some ACLs);
// 3. Verification that the signature on proposalBytes is valid;
// 4. Detect replay attacks;
type SignedProposal struct {
	// The bytes of Proposal
	ProposalBytes []byte `protobuf:"bytes,1,opt,name=proposal_bytes,json=proposalBytes,proto3" json:"proposal_bytes,omitempty"`
	// Signaure over proposalBytes; this signature is to be verified against
	// the creator identity contained in the header of the Proposal message
	// marshaled as proposalBytes
	Signature []byte `protobuf:"bytes,2,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *SignedProposal) Reset()                    { *m = SignedProposal{} }
func (m *SignedProposal) String() string            { return proto.CompactTextString(m) }
func (*SignedProposal) ProtoMessage()               {}
func (*SignedProposal) Descriptor() ([]byte, []int) { return fileDescriptor7, []int{0} }

func (m *SignedProposal) GetProposalBytes() []byte {
	if m != nil {
		return m.ProposalBytes
	}
	return nil
}

func (m *SignedProposal) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

// A Proposal is sent to an endorser for endorsement.  The proposal contains:
// 1. A header which should be unmarshaled to a Header message.  Note that
//    Header is both the header of a Proposal and of a Transaction, in that i)
//    both headers should be unmarshaled to this message; and ii) it is used to
//    compute cryptographic hashes and signatures.  The header has fields common
//    to all proposals/transactions.  In addition it has a type field for
//    additional customization. An example of this is the ChaincodeHeaderExtension
//    message used to extend the Header for type CHAINCODE.
// 2. A payload whose type depends on the header's type field.
// 3. An extension whose type depends on the header's type field.
//
// Let us see an example. For type CHAINCODE (see the Header message),
// we have the following:
// 1. The header is a Header message whose extensions field is a
//    ChaincodeHeaderExtension message.
// 2. The payload is a ChaincodeProposalPayload message.
// 3. The extension is a ChaincodeAction that might be used to ask the
//    endorsers to endorse a specific ChaincodeAction, thus emulating the
//    submitting peer model.
type Proposal struct {
	// The header of the proposal. It is the bytes of the Header
	Header []byte `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	// The payload of the proposal as defined by the type in the proposal
	// header.
	Payload []byte `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	// Optional extensions to the proposal. Its content depends on the Header's
	// type field.  For the type CHAINCODE, it might be the bytes of a
	// ChaincodeAction message.
	Extension []byte `protobuf:"bytes,3,opt,name=extension,proto3" json:"extension,omitempty"`
}

func (m *Proposal) Reset()                    { *m = Proposal{} }
func (m *Proposal) String() string            { return proto.CompactTextString(m) }
func (*Proposal) ProtoMessage()               {}
func (*Proposal) Descriptor() ([]byte, []int) { return fileDescriptor7, []int{1} }

func (m *Proposal) GetHeader() []byte {
	if m != nil {
		return m.Header
	}
	return nil
}

func (m *Proposal) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *Proposal) GetExtension() []byte {
	if m != nil {
		return m.Extension
	}
	return nil
}

// ChaincodeHeaderExtension is the Header's extentions message to be used when
// the Header's type is CHAINCODE.  This extensions is used to specify which
// chaincode to invoke and what should appear on the ledger.
type ChaincodeHeaderExtension struct {
	// The PayloadVisibility field controls to what extent the Proposal's payload
	// (recall that for the type CHAINCODE, it is ChaincodeProposalPayload
	// message) field will be visible in the final transaction and in the ledger.
	// Ideally, it would be configurable, supporting at least 3 main visibility
	// modes:
	// 1. all bytes of the payload are visible;
	// 2. only a hash of the payload is visible;
	// 3. nothing is visible.
	// Notice that the visibility function may be potentially part of the ESCC.
	// In that case it overrides PayloadVisibility field.  Finally notice that
	// this field impacts the content of ProposalResponsePayload.proposalHash.
	PayloadVisibility []byte `protobuf:"bytes,1,opt,name=payload_visibility,json=payloadVisibility,proto3" json:"payload_visibility,omitempty"`
	// The ID of the chaincode to target.
	ChaincodeId *ChaincodeID `protobuf:"bytes,2,opt,name=chaincode_id,json=chaincodeId" json:"chaincode_id,omitempty"`
}

func (m *ChaincodeHeaderExtension) Reset()                    { *m = ChaincodeHeaderExtension{} }
func (m *ChaincodeHeaderExtension) String() string            { return proto.CompactTextString(m) }
func (*ChaincodeHeaderExtension) ProtoMessage()               {}
func (*ChaincodeHeaderExtension) Descriptor() ([]byte, []int) { return fileDescriptor7, []int{2} }

func (m *ChaincodeHeaderExtension) GetPayloadVisibility() []byte {
	if m != nil {
		return m.PayloadVisibility
	}
	return nil
}

func (m *ChaincodeHeaderExtension) GetChaincodeId() *ChaincodeID {
	if m != nil {
		return m.ChaincodeId
	}
	return nil
}

// ChaincodeProposalPayload is the Proposal's payload message to be used when
// the Header's type is CHAINCODE.  It contains the arguments for this
// invocation.
type ChaincodeProposalPayload struct {
	// Input contains the arguments for this invocation. If this invocation
	// deploys a new chaincode, ESCC/VSCC are part of this field.
	Input []byte `protobuf:"bytes,1,opt,name=input,proto3" json:"input,omitempty"`
	// TransientMap contains data (e.g. cryptographic material) that might be used
	// to implement some form of application-level confidentiality. The contents
	// of this field are supposed to always be omitted from the transaction and
	// excluded from the ledger.
	TransientMap map[string][]byte `protobuf:"bytes,2,rep,name=TransientMap" json:"TransientMap,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (m *ChaincodeProposalPayload) Reset()                    { *m = ChaincodeProposalPayload{} }
func (m *ChaincodeProposalPayload) String() string            { return proto.CompactTextString(m) }
func (*ChaincodeProposalPayload) ProtoMessage()               {}
func (*ChaincodeProposalPayload) Descriptor() ([]byte, []int) { return fileDescriptor7, []int{3} }

func (m *ChaincodeProposalPayload) GetInput() []byte {
	if m != nil {
		return m.Input
	}
	return nil
}

func (m *ChaincodeProposalPayload) GetTransientMap() map[string][]byte {
	if m != nil {
		return m.TransientMap
	}
	return nil
}

// ChaincodeAction contains the actions the events generated by the execution
// of the chaincode.
type ChaincodeAction struct {
	// This field contains the read set and the write set produced by the
	// chaincode executing this invocation.
	Results []byte `protobuf:"bytes,1,opt,name=results,proto3" json:"results,omitempty"`
	// This field contains the events generated by the chaincode executing this
	// invocation.
	Events []byte `protobuf:"bytes,2,opt,name=events,proto3" json:"events,omitempty"`
	// This field contains the result of executing this invocation.
	Response *Response `protobuf:"bytes,3,opt,name=response" json:"response,omitempty"`
	// This field contains the ChaincodeID of executing this invocation. Endorser
	// will set it with the ChaincodeID called by endorser while simulating proposal.
	// Committer will validate the version matching with latest chaincode version.
	// Adding ChaincodeID to keep version opens up the possibility of multiple
	// ChaincodeAction per transaction.
	ChaincodeId *ChaincodeID `protobuf:"bytes,4,opt,name=chaincode_id,json=chaincodeId" json:"chaincode_id,omitempty"`
}

func (m *ChaincodeAction) Reset()                    { *m = ChaincodeAction{} }
func (m *ChaincodeAction) String() string            { return proto.CompactTextString(m) }
func (*ChaincodeAction) ProtoMessage()               {}
func (*ChaincodeAction) Descriptor() ([]byte, []int) { return fileDescriptor7, []int{4} }

func (m *ChaincodeAction) GetResults() []byte {
	if m != nil {
		return m.Results
	}
	return nil
}

func (m *ChaincodeAction) GetEvents() []byte {
	if m != nil {
		return m.Events
	}
	return nil
}

func (m *ChaincodeAction) GetResponse() *Response {
	if m != nil {
		return m.Response
	}
	return nil
}

func (m *ChaincodeAction) GetChaincodeId() *ChaincodeID {
	if m != nil {
		return m.ChaincodeId
	}
	return nil
}

func init() {
	proto.RegisterType((*SignedProposal)(nil), "protos.SignedProposal")
	proto.RegisterType((*Proposal)(nil), "protos.Proposal")
	proto.RegisterType((*ChaincodeHeaderExtension)(nil), "protos.ChaincodeHeaderExtension")
	proto.RegisterType((*ChaincodeProposalPayload)(nil), "protos.ChaincodeProposalPayload")
	proto.RegisterType((*ChaincodeAction)(nil), "protos.ChaincodeAction")
}

func init() { proto.RegisterFile("peer/proposal.proto", fileDescriptor7) }

var fileDescriptor7 = []byte{
	// 452 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x93, 0x4b, 0x6f, 0xd3, 0x40,
	0x10, 0xc7, 0xe5, 0x04, 0xfa, 0x98, 0x84, 0x3e, 0xb6, 0x15, 0xb2, 0xa2, 0x1e, 0x2a, 0x4b, 0x48,
	0x15, 0x02, 0x5b, 0x04, 0x09, 0x21, 0x2e, 0x88, 0x40, 0x25, 0x7a, 0x40, 0xaa, 0x0c, 0xf4, 0xd0,
	0x4b, 0xb4, 0xb6, 0x07, 0x67, 0x15, 0xb3, 0x6b, 0xed, 0xae, 0x23, 0x72, 0xe4, 0xe3, 0xf0, 0x51,
	0xf8, 0x56, 0x68, 0xbd, 0x8f, 0x36, 0xe4, 0xd2, 0x53, 0x32, 0x33, 0xff, 0xf9, 0xcd, 0x6b, 0x0d,
	0x27, 0x2d, 0xa2, 0xcc, 0x5a, 0x29, 0x5a, 0xa1, 0x68, 0x93, 0xb6, 0x52, 0x68, 0x41, 0x76, 0xfa,
	0x1f, 0x35, 0x39, 0xed, 0x83, 0xe5, 0x82, 0x32, 0x5e, 0x8a, 0x0a, 0x6d, 0x74, 0x72, 0xb6, 0x91,
	0x32, 0x97, 0xa8, 0x5a, 0xc1, 0x95, 0x8b, 0x26, 0xdf, 0xe1, 0xe0, 0x2b, 0xab, 0x39, 0x56, 0xd7,
	0x4e, 0x40, 0x9e, 0xc1, 0x41, 0x10, 0x17, 0x6b, 0x8d, 0x2a, 0x8e, 0xce, 0xa3, 0x8b, 0x71, 0xfe,
	0xc4, 0x7b, 0x67, 0xc6, 0x49, 0xce, 0x60, 0x5f, 0xb1, 0x9a, 0x53, 0xdd, 0x49, 0x8c, 0x07, 0xbd,
	0xe2, 0xce, 0x91, 0xdc, 0xc2, 0x5e, 0x00, 0x3e, 0x85, 0x9d, 0x05, 0xd2, 0x0a, 0xa5, 0x03, 0x39,
	0x8b, 0xc4, 0xb0, 0xdb, 0xd2, 0x75, 0x23, 0x68, 0xe5, 0xf2, 0xbd, 0x69, 0xd8, 0xf8, 0x4b, 0x23,
	0x57, 0x4c, 0xf0, 0x78, 0x68, 0xd9, 0xc1, 0x91, 0xfc, 0x8e, 0x20, 0xfe, 0xe8, 0x87, 0xfc, 0xdc,
	0xb3, 0x2e, 0x7d, 0x90, 0xbc, 0x04, 0xe2, 0x28, 0xf3, 0x15, 0x53, 0xac, 0x60, 0x0d, 0xd3, 0x6b,
	0x57, 0xf8, 0xd8, 0x45, 0x6e, 0x42, 0x80, 0xbc, 0x81, 0x71, 0xd8, 0xd7, 0x9c, 0xd9, 0x46, 0x46,
	0xd3, 0x13, 0xbb, 0x1c, 0x95, 0x86, 0x32, 0x57, 0x9f, 0xf2, 0x51, 0x10, 0x5e, 0x55, 0xc9, 0xdf,
	0xfb, 0x3d, 0xf8, 0x49, 0xaf, 0x5d, 0xfb, 0xa7, 0xf0, 0x98, 0xf1, 0xb6, 0xd3, 0xae, 0xac, 0x35,
	0xc8, 0x0d, 0x8c, 0xbf, 0x49, 0xca, 0x15, 0x43, 0xae, 0xbf, 0xd0, 0x36, 0x1e, 0x9c, 0x0f, 0x2f,
	0x46, 0xd3, 0xe9, 0x56, 0xa9, 0xff, 0x68, 0xe9, 0xfd, 0xa4, 0x4b, 0xae, 0xe5, 0x3a, 0xdf, 0xe0,
	0x4c, 0xde, 0xc3, 0xf1, 0x96, 0x84, 0x1c, 0xc1, 0x70, 0x89, 0x76, 0xee, 0xfd, 0xdc, 0xfc, 0x35,
	0x4d, 0xad, 0x68, 0xd3, 0xf9, 0x5b, 0x59, 0xe3, 0xdd, 0xe0, 0x6d, 0x94, 0xfc, 0x89, 0xe0, 0x30,
	0x54, 0xff, 0x50, 0x6a, 0xb3, 0xc6, 0x18, 0x76, 0x25, 0xaa, 0xae, 0xd1, 0xfe, 0xfa, 0xde, 0x34,
	0xd7, 0xc4, 0x15, 0x72, 0xad, 0x1c, 0xc8, 0x59, 0xe4, 0x05, 0xec, 0xf9, 0xa7, 0xd5, 0x9f, 0x6c,
	0x34, 0x3d, 0xf2, 0xa3, 0xe5, 0xce, 0x9f, 0x07, 0xc5, 0xd6, 0xde, 0x1f, 0x3d, 0x6c, 0xef, 0xb3,
	0x16, 0x9e, 0x0b, 0x59, 0xa7, 0x8c, 0x2f, 0x1b, 0x5a, 0xa8, 0x1f, 0xa2, 0xe3, 0x15, 0x35, 0x0d,
	0x1b, 0x4f, 0xaf, 0xf3, 0x04, 0xf3, 0xe8, 0x67, 0x87, 0x77, 0xbb, 0x2c, 0x97, 0xb4, 0xc6, 0xdb,
	0x57, 0x35, 0xd3, 0x8b, 0xae, 0x48, 0x4b, 0xf1, 0x33, 0xdb, 0x62, 0x64, 0x9e, 0x91, 0x59, 0x46,
	0x66, 0x18, 0x85, 0xfd, 0xb8, 0x5e, 0xff, 0x0b, 0x00, 0x00, 0xff, 0xff, 0xef, 0xcd, 0xe5, 0x01,
	0x7a, 0x03, 0x00, 0x00,
}
