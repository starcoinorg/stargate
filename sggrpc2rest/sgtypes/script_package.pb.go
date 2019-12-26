// Code generated by protoc-gen-go. DO NOT EDIT.
// source: script_package.proto

package sgtypes

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

type ChannelScriptPackage struct {
	PackageName          string        `protobuf:"bytes,1,opt,name=package_name,json=packageName,proto3" json:"package_name,omitempty"`
	Scripts              []*ScriptCode `protobuf:"bytes,2,rep,name=scripts,proto3" json:"scripts,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *ChannelScriptPackage) Reset()         { *m = ChannelScriptPackage{} }
func (m *ChannelScriptPackage) String() string { return proto.CompactTextString(m) }
func (*ChannelScriptPackage) ProtoMessage()    {}
func (*ChannelScriptPackage) Descriptor() ([]byte, []int) {
	return fileDescriptor_400095609cdd243d, []int{0}
}

func (m *ChannelScriptPackage) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChannelScriptPackage.Unmarshal(m, b)
}
func (m *ChannelScriptPackage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChannelScriptPackage.Marshal(b, m, deterministic)
}
func (m *ChannelScriptPackage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChannelScriptPackage.Merge(m, src)
}
func (m *ChannelScriptPackage) XXX_Size() int {
	return xxx_messageInfo_ChannelScriptPackage.Size(m)
}
func (m *ChannelScriptPackage) XXX_DiscardUnknown() {
	xxx_messageInfo_ChannelScriptPackage.DiscardUnknown(m)
}

var xxx_messageInfo_ChannelScriptPackage proto.InternalMessageInfo

func (m *ChannelScriptPackage) GetPackageName() string {
	if m != nil {
		return m.PackageName
	}
	return ""
}

func (m *ChannelScriptPackage) GetScripts() []*ScriptCode {
	if m != nil {
		return m.Scripts
	}
	return nil
}

type ScriptCode struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	SourceCode           string   `protobuf:"bytes,2,opt,name=source_code,json=sourceCode,proto3" json:"source_code,omitempty"`
	ByteCode             []byte   `protobuf:"bytes,3,opt,name=byte_code,json=byteCode,proto3" json:"byte_code,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ScriptCode) Reset()         { *m = ScriptCode{} }
func (m *ScriptCode) String() string { return proto.CompactTextString(m) }
func (*ScriptCode) ProtoMessage()    {}
func (*ScriptCode) Descriptor() ([]byte, []int) {
	return fileDescriptor_400095609cdd243d, []int{1}
}

func (m *ScriptCode) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ScriptCode.Unmarshal(m, b)
}
func (m *ScriptCode) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ScriptCode.Marshal(b, m, deterministic)
}
func (m *ScriptCode) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ScriptCode.Merge(m, src)
}
func (m *ScriptCode) XXX_Size() int {
	return xxx_messageInfo_ScriptCode.Size(m)
}
func (m *ScriptCode) XXX_DiscardUnknown() {
	xxx_messageInfo_ScriptCode.DiscardUnknown(m)
}

var xxx_messageInfo_ScriptCode proto.InternalMessageInfo

func (m *ScriptCode) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ScriptCode) GetSourceCode() string {
	if m != nil {
		return m.SourceCode
	}
	return ""
}

func (m *ScriptCode) GetByteCode() []byte {
	if m != nil {
		return m.ByteCode
	}
	return nil
}

func init() {
	proto.RegisterType((*ChannelScriptPackage)(nil), "sgtypes.ChannelScriptPackage")
	proto.RegisterType((*ScriptCode)(nil), "sgtypes.ScriptCode")
}

func init() { proto.RegisterFile("script_package.proto", fileDescriptor_400095609cdd243d) }

var fileDescriptor_400095609cdd243d = []byte{
	// 185 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4c, 0x8f, 0x31, 0x0f, 0x82, 0x30,
	0x10, 0x85, 0x03, 0x18, 0x91, 0x83, 0xa9, 0x32, 0x90, 0x38, 0x88, 0x4c, 0x2c, 0x32, 0xe8, 0x4f,
	0x60, 0x37, 0x06, 0x77, 0x49, 0x29, 0x17, 0x30, 0x0a, 0x6d, 0x68, 0x1d, 0xf8, 0xf7, 0x86, 0xb6,
	0x46, 0xb7, 0xcb, 0xf7, 0xde, 0xfb, 0x92, 0x83, 0x58, 0xb2, 0xe9, 0x21, 0x54, 0x2d, 0x28, 0x7b,
	0xd2, 0x0e, 0x0b, 0x31, 0x71, 0xc5, 0x89, 0x2f, 0x3b, 0x35, 0x0b, 0x94, 0x59, 0x0f, 0x71, 0xd9,
	0xd3, 0x71, 0xc4, 0xd7, 0x4d, 0xf7, 0xae, 0xa6, 0x46, 0x0e, 0x10, 0xd9, 0x45, 0x3d, 0xd2, 0x01,
	0x13, 0x27, 0x75, 0xf2, 0xa0, 0x0a, 0x2d, 0xbb, 0xd0, 0x01, 0xc9, 0x11, 0x7c, 0xe3, 0x96, 0x89,
	0x9b, 0x7a, 0x79, 0x78, 0xda, 0x16, 0xd6, 0x5a, 0x18, 0x57, 0xc9, 0x5b, 0xac, 0xbe, 0x9d, 0xec,
	0x0e, 0xf0, 0xc3, 0x84, 0xc0, 0xea, 0xcf, 0xab, 0x6f, 0xb2, 0x87, 0x50, 0xf2, 0xf7, 0xc4, 0xb0,
	0x66, 0xbc, 0xc5, 0xc4, 0xd5, 0x11, 0x18, 0xa4, 0x47, 0x3b, 0x08, 0x9a, 0x59, 0xd9, 0xd8, 0x4b,
	0x9d, 0x3c, 0xaa, 0x36, 0x0b, 0x58, 0xc2, 0x66, 0xad, 0x3f, 0x3b, 0x7f, 0x02, 0x00, 0x00, 0xff,
	0xff, 0x7e, 0x13, 0x9d, 0xad, 0xf1, 0x00, 0x00, 0x00,
}