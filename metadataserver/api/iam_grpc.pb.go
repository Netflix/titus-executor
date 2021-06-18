// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package iamapi

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// IAMClient is the client API for IAM service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IAMClient interface {
	AssumeRole(ctx context.Context, in *AssumeRoleRequest, opts ...grpc.CallOption) (*AssumeRoleResponse, error)
}

type iAMClient struct {
	cc grpc.ClientConnInterface
}

func NewIAMClient(cc grpc.ClientConnInterface) IAMClient {
	return &iAMClient{cc}
}

func (c *iAMClient) AssumeRole(ctx context.Context, in *AssumeRoleRequest, opts ...grpc.CallOption) (*AssumeRoleResponse, error) {
	out := new(AssumeRoleResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.executor.metadataserver.IAM/AssumeRole", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IAMServer is the server API for IAM service.
// All implementations should embed UnimplementedIAMServer
// for forward compatibility
type IAMServer interface {
	AssumeRole(context.Context, *AssumeRoleRequest) (*AssumeRoleResponse, error)
}

// UnimplementedIAMServer should be embedded to have forward compatible implementations.
type UnimplementedIAMServer struct {
}

func (UnimplementedIAMServer) AssumeRole(context.Context, *AssumeRoleRequest) (*AssumeRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssumeRole not implemented")
}

// UnsafeIAMServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IAMServer will
// result in compilation errors.
type UnsafeIAMServer interface {
	mustEmbedUnimplementedIAMServer()
}

func RegisterIAMServer(s grpc.ServiceRegistrar, srv IAMServer) {
	s.RegisterService(&IAM_ServiceDesc, srv)
}

func _IAM_AssumeRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AssumeRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IAMServer).AssumeRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.executor.metadataserver.IAM/AssumeRole",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IAMServer).AssumeRole(ctx, req.(*AssumeRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IAM_ServiceDesc is the grpc.ServiceDesc for IAM service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IAM_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.executor.metadataserver.IAM",
	HandlerType: (*IAMServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AssumeRole",
			Handler:    _IAM_AssumeRole_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "iam.proto",
}
