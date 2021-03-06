// Code generated by protoc-gen-go.
// source: github.com/HailoOSS/login-service/proto/revokeservice/revokeservice.proto
// DO NOT EDIT!

/*
Package com_HailoOSS_service_login_revokeservice is a generated protocol buffer package.

It is generated from these files:
	github.com/HailoOSS/login-service/proto/revokeservice/revokeservice.proto

It has these top-level messages:
	Request
	Response
*/
package com_HailoOSS_service_login_revokeservice

import proto "github.com/HailoOSS/protobuf/proto"
import json "encoding/json"
import math "math"
import com_HailoOSS_service_login "github.com/HailoOSS/login-service/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type Request struct {
	Endpoint         *com_HailoOSS_service_login.Endpoint `protobuf:"bytes,1,req,name=endpoint" json:"endpoint,omitempty"`
	XXX_unrecognized []byte                               `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}

func (m *Request) GetEndpoint() *com_HailoOSS_service_login.Endpoint {
	if m != nil {
		return m.Endpoint
	}
	return nil
}

type Response struct {
	XXX_unrecognized []byte `json:"-"`
}

func (m *Response) Reset()         { *m = Response{} }
func (m *Response) String() string { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()    {}

func init() {
}
