// Code generated by protoc-gen-go.
// source: github.com/HailoOSS/login-service/proto/readlogin/readlogin.proto
// DO NOT EDIT!

/*
Package com_HailoOSS_service_login_readlogin is a generated protocol buffer package.

It is generated from these files:
	github.com/HailoOSS/login-service/proto/readlogin/readlogin.proto

It has these top-level messages:
	Request
	Response
	Login
*/
package com_HailoOSS_service_login_readlogin

import proto "github.com/HailoOSS/protobuf/proto"
import json "encoding/json"
import math "math"
import com_HailoOSS_service_login "github.com/HailoOSS/login-service/proto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = &json.SyntaxError{}
var _ = math.Inf

type Request struct {
	// which user
	Application *string `protobuf:"bytes,1,req,name=application" json:"application,omitempty"`
	Uid         *string `protobuf:"bytes,2,req,name=uid" json:"uid,omitempty"`
	// specify a time range to search between
	RangeStart *int64 `protobuf:"varint,3,opt,name=rangeStart" json:"rangeStart,omitempty"`
	RangeEnd   *int64 `protobuf:"varint,4,opt,name=rangeEnd" json:"rangeEnd,omitempty"`
	// paginate
	LastId           *string `protobuf:"bytes,5,opt,name=lastId" json:"lastId,omitempty"`
	Count            *int32  `protobuf:"varint,6,opt,name=count,def=10" json:"count,omitempty"`
	XXX_unrecognized []byte  `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}

const Default_Request_Count int32 = 10

func (m *Request) GetApplication() string {
	if m != nil && m.Application != nil {
		return *m.Application
	}
	return ""
}

func (m *Request) GetUid() string {
	if m != nil && m.Uid != nil {
		return *m.Uid
	}
	return ""
}

func (m *Request) GetRangeStart() int64 {
	if m != nil && m.RangeStart != nil {
		return *m.RangeStart
	}
	return 0
}

func (m *Request) GetRangeEnd() int64 {
	if m != nil && m.RangeEnd != nil {
		return *m.RangeEnd
	}
	return 0
}

func (m *Request) GetLastId() string {
	if m != nil && m.LastId != nil {
		return *m.LastId
	}
	return ""
}

func (m *Request) GetCount() int32 {
	if m != nil && m.Count != nil {
		return *m.Count
	}
	return Default_Request_Count
}

type Response struct {
	Login            []*Login `protobuf:"bytes,1,rep,name=login" json:"login,omitempty"`
	LastId           *string  `protobuf:"bytes,2,opt,name=lastId" json:"lastId,omitempty"`
	XXX_unrecognized []byte   `json:"-"`
}

func (m *Response) Reset()         { *m = Response{} }
func (m *Response) String() string { return proto.CompactTextString(m) }
func (*Response) ProtoMessage()    {}

func (m *Response) GetLogin() []*Login {
	if m != nil {
		return m.Login
	}
	return nil
}

func (m *Response) GetLastId() string {
	if m != nil && m.LastId != nil {
		return *m.LastId
	}
	return ""
}

type Login struct {
	Application       *string                                `protobuf:"bytes,1,opt,name=application" json:"application,omitempty"`
	Uid               *string                                `protobuf:"bytes,2,opt,name=uid" json:"uid,omitempty"`
	LoggedInTimestamp *int64                                 `protobuf:"varint,3,opt,name=loggedInTimestamp" json:"loggedInTimestamp,omitempty"`
	Mech              *string                                `protobuf:"bytes,4,opt,name=mech" json:"mech,omitempty"`
	DeviceType        *string                                `protobuf:"bytes,5,opt,name=deviceType" json:"deviceType,omitempty"`
	Meta              []*com_HailoOSS_service_login.KeyValue `protobuf:"bytes,6,rep,name=meta" json:"meta,omitempty"`
	XXX_unrecognized  []byte                                 `json:"-"`
}

func (m *Login) Reset()         { *m = Login{} }
func (m *Login) String() string { return proto.CompactTextString(m) }
func (*Login) ProtoMessage()    {}

func (m *Login) GetApplication() string {
	if m != nil && m.Application != nil {
		return *m.Application
	}
	return ""
}

func (m *Login) GetUid() string {
	if m != nil && m.Uid != nil {
		return *m.Uid
	}
	return ""
}

func (m *Login) GetLoggedInTimestamp() int64 {
	if m != nil && m.LoggedInTimestamp != nil {
		return *m.LoggedInTimestamp
	}
	return 0
}

func (m *Login) GetMech() string {
	if m != nil && m.Mech != nil {
		return *m.Mech
	}
	return ""
}

func (m *Login) GetDeviceType() string {
	if m != nil && m.DeviceType != nil {
		return *m.DeviceType
	}
	return ""
}

func (m *Login) GetMeta() []*com_HailoOSS_service_login.KeyValue {
	if m != nil {
		return m.Meta
	}
	return nil
}

func init() {
}
