// Code generated by protoc-gen-go.
// source: github.com/HailoOSS/login-service/proto/deletesession/deletesession.proto
// DO NOT EDIT!

/*
Package com_HailoOSS_service_login_deletesession is a generated protocol buffer package.

It is generated from these files:
	github.com/HailoOSS/login-service/proto/deletesession/deletesession.proto

It has these top-level messages:
	Request
	Response
*/
package com_HailoOSS_service_login_deletesession

import proto "github.com/HailoOSS/protobuf/proto"
import json "encoding/json"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type Request struct {
	SessId           *string `protobuf:"bytes,1,req,name=sessId" json:"sessId,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}

func (m *Request) GetSessId() string {
	if m != nil && m.SessId != nil {
		return *m.SessId
	}
	return ""
}

type Response struct {
	XXX_unrecognized []byte `json:"-"`
}

func (m *Response) Reset()         { *m = Response{} }
func (m *Response) String() string { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()    {}

func init() {
}