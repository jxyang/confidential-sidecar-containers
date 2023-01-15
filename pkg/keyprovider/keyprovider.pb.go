// Code generated by protoc-gen-go. DO NOT EDIT.
// source: keyprovider.proto

package keyprovider

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type KeyProviderKeyWrapProtocolInput struct {
	KeyProviderKeyWrapProtocolInput []byte   `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolInput,proto3" json:"KeyProviderKeyWrapProtocolInput,omitempty"`
	XXX_NoUnkeyedLiteral            struct{} `json:"-"`
	XXX_unrecognized                []byte   `json:"-"`
	XXX_sizecache                   int32    `json:"-"`
}

func (m *KeyProviderKeyWrapProtocolInput) Reset()         { *m = KeyProviderKeyWrapProtocolInput{} }
func (m *KeyProviderKeyWrapProtocolInput) String() string { return proto.CompactTextString(m) }
func (*KeyProviderKeyWrapProtocolInput) ProtoMessage()    {}
func (*KeyProviderKeyWrapProtocolInput) Descriptor() ([]byte, []int) {
	return fileDescriptor_da74c8e785ad390c, []int{0}
}

func (m *KeyProviderKeyWrapProtocolInput) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Unmarshal(m, b)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Marshal(b, m, deterministic)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Merge(m, src)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_Size() int {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolInput.Size(m)
}
func (m *KeyProviderKeyWrapProtocolInput) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyProviderKeyWrapProtocolInput.DiscardUnknown(m)
}

var xxx_messageInfo_KeyProviderKeyWrapProtocolInput proto.InternalMessageInfo

func (m *KeyProviderKeyWrapProtocolInput) GetKeyProviderKeyWrapProtocolInput() []byte {
	if m != nil {
		return m.KeyProviderKeyWrapProtocolInput
	}
	return nil
}

type KeyProviderKeyWrapProtocolOutput struct {
	KeyProviderKeyWrapProtocolOutput []byte   `protobuf:"bytes,1,opt,name=KeyProviderKeyWrapProtocolOutput,proto3" json:"KeyProviderKeyWrapProtocolOutput,omitempty"`
	XXX_NoUnkeyedLiteral             struct{} `json:"-"`
	XXX_unrecognized                 []byte   `json:"-"`
	XXX_sizecache                    int32    `json:"-"`
}

func (m *KeyProviderKeyWrapProtocolOutput) Reset()         { *m = KeyProviderKeyWrapProtocolOutput{} }
func (m *KeyProviderKeyWrapProtocolOutput) String() string { return proto.CompactTextString(m) }
func (*KeyProviderKeyWrapProtocolOutput) ProtoMessage()    {}
func (*KeyProviderKeyWrapProtocolOutput) Descriptor() ([]byte, []int) {
	return fileDescriptor_da74c8e785ad390c, []int{1}
}

func (m *KeyProviderKeyWrapProtocolOutput) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Unmarshal(m, b)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Marshal(b, m, deterministic)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Merge(src proto.Message) {
	xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Merge(m, src)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_Size() int {
	return xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.Size(m)
}
func (m *KeyProviderKeyWrapProtocolOutput) XXX_DiscardUnknown() {
	xxx_messageInfo_KeyProviderKeyWrapProtocolOutput.DiscardUnknown(m)
}

var xxx_messageInfo_KeyProviderKeyWrapProtocolOutput proto.InternalMessageInfo

func (m *KeyProviderKeyWrapProtocolOutput) GetKeyProviderKeyWrapProtocolOutput() []byte {
	if m != nil {
		return m.KeyProviderKeyWrapProtocolOutput
	}
	return nil
}

type HelloRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HelloRequest) Reset()         { *m = HelloRequest{} }
func (m *HelloRequest) String() string { return proto.CompactTextString(m) }
func (*HelloRequest) ProtoMessage()    {}
func (*HelloRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_da74c8e785ad390c, []int{2}
}

func (m *HelloRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HelloRequest.Unmarshal(m, b)
}
func (m *HelloRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HelloRequest.Marshal(b, m, deterministic)
}
func (m *HelloRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HelloRequest.Merge(m, src)
}
func (m *HelloRequest) XXX_Size() int {
	return xxx_messageInfo_HelloRequest.Size(m)
}
func (m *HelloRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_HelloRequest.DiscardUnknown(m)
}

var xxx_messageInfo_HelloRequest proto.InternalMessageInfo

func (m *HelloRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

// The response message containing the greetings
type HelloReply struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HelloReply) Reset()         { *m = HelloReply{} }
func (m *HelloReply) String() string { return proto.CompactTextString(m) }
func (*HelloReply) ProtoMessage()    {}
func (*HelloReply) Descriptor() ([]byte, []int) {
	return fileDescriptor_da74c8e785ad390c, []int{3}
}

func (m *HelloReply) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HelloReply.Unmarshal(m, b)
}
func (m *HelloReply) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HelloReply.Marshal(b, m, deterministic)
}
func (m *HelloReply) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HelloReply.Merge(m, src)
}
func (m *HelloReply) XXX_Size() int {
	return xxx_messageInfo_HelloReply.Size(m)
}
func (m *HelloReply) XXX_DiscardUnknown() {
	xxx_messageInfo_HelloReply.DiscardUnknown(m)
}

var xxx_messageInfo_HelloReply proto.InternalMessageInfo

func (m *HelloReply) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func init() {
	proto.RegisterType((*KeyProviderKeyWrapProtocolInput)(nil), "keyProviderKeyWrapProtocolInput")
	proto.RegisterType((*KeyProviderKeyWrapProtocolOutput)(nil), "keyProviderKeyWrapProtocolOutput")
	proto.RegisterType((*HelloRequest)(nil), "HelloRequest")
	proto.RegisterType((*HelloReply)(nil), "HelloReply")
}

func init() { proto.RegisterFile("keyprovider.proto", fileDescriptor_da74c8e785ad390c) }

var fileDescriptor_da74c8e785ad390c = []byte{
	// 287 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xb1, 0x4e, 0xc3, 0x30,
	0x10, 0x86, 0x5b, 0x09, 0x51, 0x7a, 0x94, 0x01, 0x4f, 0x55, 0x97, 0x06, 0x0f, 0xa8, 0x4b, 0x5d,
	0x09, 0xde, 0x80, 0xa9, 0x90, 0x81, 0x28, 0x51, 0x85, 0xc4, 0xe6, 0x26, 0x47, 0xb0, 0x92, 0xd8,
	0xc6, 0x76, 0x22, 0xf9, 0x7d, 0x79, 0x10, 0x94, 0x28, 0x85, 0x2c, 0x90, 0x85, 0xcd, 0xf6, 0x7d,
	0xbe, 0x4f, 0xff, 0xe9, 0xe0, 0xba, 0x40, 0xaf, 0x8d, 0x6a, 0x44, 0x86, 0x86, 0x69, 0xa3, 0x9c,
	0xa2, 0x05, 0xac, 0x0b, 0xf4, 0x51, 0xff, 0x18, 0xa2, 0x7f, 0x31, 0x5c, 0x47, 0x6d, 0x29, 0x55,
	0xe5, 0xa3, 0xd4, 0xb5, 0x23, 0x7b, 0x58, 0x87, 0x7f, 0x23, 0xcb, 0x69, 0x30, 0xdd, 0x2c, 0xe2,
	0x31, 0x8c, 0x4a, 0x08, 0x7e, 0x97, 0x3d, 0xd7, 0xae, 0xb5, 0x3d, 0x41, 0x10, 0x8e, 0x30, 0xbd,
	0x6e, 0x94, 0xa3, 0x14, 0x16, 0x7b, 0x2c, 0x4b, 0x15, 0xe3, 0x47, 0x8d, 0xd6, 0x11, 0x02, 0x67,
	0x92, 0x57, 0xd8, 0xfd, 0x9f, 0xc7, 0xdd, 0x99, 0xde, 0x02, 0xf4, 0x8c, 0x2e, 0x3d, 0x59, 0xc2,
	0xac, 0x42, 0x6b, 0x79, 0x7e, 0x82, 0x4e, 0xd7, 0xbb, 0xcf, 0x29, 0x90, 0x81, 0x30, 0x41, 0xd3,
	0x88, 0x14, 0x49, 0x04, 0xb3, 0x56, 0x1c, 0xa2, 0x27, 0x01, 0x1b, 0x99, 0xe4, 0xea, 0x86, 0x8d,
	0xc5, 0xa7, 0x13, 0x12, 0xc3, 0xfc, 0x20, 0xff, 0xb9, 0xe7, 0x06, 0x2e, 0x12, 0xee, 0xbb, 0x9c,
	0xe4, 0x8a, 0x0d, 0x67, 0xb2, 0xba, 0x64, 0x3f, 0xf1, 0xe9, 0xe4, 0xe1, 0xf0, 0x9a, 0xe4, 0xc2,
	0xbd, 0xd7, 0x47, 0x96, 0xaa, 0x6a, 0x97, 0x2a, 0xe9, 0xb8, 0x90, 0x68, 0xb6, 0x42, 0x36, 0x68,
	0x9d, 0xc8, 0xb9, 0x13, 0x4a, 0xda, 0xb6, 0xf0, 0x26, 0x32, 0x94, 0x4e, 0xf0, 0x72, 0x6b, 0x45,
	0x86, 0x29, 0x37, 0xdb, 0x6f, 0xda, 0xee, 0x74, 0x91, 0xef, 0x06, 0xcb, 0x76, 0x3c, 0xef, 0xb6,
	0xed, 0xfe, 0x2b, 0x00, 0x00, 0xff, 0xff, 0xc9, 0xe8, 0x3b, 0x53, 0x82, 0x02, 0x00, 0x00,
}
