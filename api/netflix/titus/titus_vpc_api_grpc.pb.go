// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package titus

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

// UserIPServiceClient is the client API for UserIPService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type UserIPServiceClient interface {
	// Static IP Address flow
	AllocateAddress(ctx context.Context, in *AllocateAddressRequest, opts ...grpc.CallOption) (*AllocateAddressResponse, error)
	GetAllocation(ctx context.Context, in *GetAllocationRequest, opts ...grpc.CallOption) (*GetAllocationResponse, error)
}

type userIPServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewUserIPServiceClient(cc grpc.ClientConnInterface) UserIPServiceClient {
	return &userIPServiceClient{cc}
}

func (c *userIPServiceClient) AllocateAddress(ctx context.Context, in *AllocateAddressRequest, opts ...grpc.CallOption) (*AllocateAddressResponse, error) {
	out := new(AllocateAddressResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.UserIPService/AllocateAddress", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userIPServiceClient) GetAllocation(ctx context.Context, in *GetAllocationRequest, opts ...grpc.CallOption) (*GetAllocationResponse, error) {
	out := new(GetAllocationResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.UserIPService/GetAllocation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UserIPServiceServer is the server API for UserIPService service.
// All implementations must embed UnimplementedUserIPServiceServer
// for forward compatibility
type UserIPServiceServer interface {
	// Static IP Address flow
	AllocateAddress(context.Context, *AllocateAddressRequest) (*AllocateAddressResponse, error)
	GetAllocation(context.Context, *GetAllocationRequest) (*GetAllocationResponse, error)
	mustEmbedUnimplementedUserIPServiceServer()
}

// UnimplementedUserIPServiceServer must be embedded to have forward compatible implementations.
type UnimplementedUserIPServiceServer struct {
}

func (UnimplementedUserIPServiceServer) AllocateAddress(context.Context, *AllocateAddressRequest) (*AllocateAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllocateAddress not implemented")
}
func (UnimplementedUserIPServiceServer) GetAllocation(context.Context, *GetAllocationRequest) (*GetAllocationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAllocation not implemented")
}
func (UnimplementedUserIPServiceServer) mustEmbedUnimplementedUserIPServiceServer() {}

// UnsafeUserIPServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to UserIPServiceServer will
// result in compilation errors.
type UnsafeUserIPServiceServer interface {
	mustEmbedUnimplementedUserIPServiceServer()
}

func RegisterUserIPServiceServer(s grpc.ServiceRegistrar, srv UserIPServiceServer) {
	s.RegisterService(&UserIPService_ServiceDesc, srv)
}

func _UserIPService_AllocateAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AllocateAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserIPServiceServer).AllocateAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.UserIPService/AllocateAddress",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserIPServiceServer).AllocateAddress(ctx, req.(*AllocateAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserIPService_GetAllocation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAllocationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserIPServiceServer).GetAllocation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.UserIPService/GetAllocation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserIPServiceServer).GetAllocation(ctx, req.(*GetAllocationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// UserIPService_ServiceDesc is the grpc.ServiceDesc for UserIPService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var UserIPService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.UserIPService",
	HandlerType: (*UserIPServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AllocateAddress",
			Handler:    _UserIPService_AllocateAddress_Handler,
		},
		{
			MethodName: "GetAllocation",
			Handler:    _UserIPService_GetAllocation_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "netflix/titus/titus_vpc_api.proto",
}

// ValidatorIPServiceClient is the client API for ValidatorIPService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ValidatorIPServiceClient interface {
	ValidateAllocation(ctx context.Context, in *ValidationRequest, opts ...grpc.CallOption) (*ValidationResponse, error)
	ValidateAllocationParameters(ctx context.Context, in *ParametersValidationRequest, opts ...grpc.CallOption) (*ParametersValidationResponse, error)
}

type validatorIPServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewValidatorIPServiceClient(cc grpc.ClientConnInterface) ValidatorIPServiceClient {
	return &validatorIPServiceClient{cc}
}

func (c *validatorIPServiceClient) ValidateAllocation(ctx context.Context, in *ValidationRequest, opts ...grpc.CallOption) (*ValidationResponse, error) {
	out := new(ValidationResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.ValidatorIPService/ValidateAllocation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *validatorIPServiceClient) ValidateAllocationParameters(ctx context.Context, in *ParametersValidationRequest, opts ...grpc.CallOption) (*ParametersValidationResponse, error) {
	out := new(ParametersValidationResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.ValidatorIPService/ValidateAllocationParameters", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ValidatorIPServiceServer is the server API for ValidatorIPService service.
// All implementations must embed UnimplementedValidatorIPServiceServer
// for forward compatibility
type ValidatorIPServiceServer interface {
	ValidateAllocation(context.Context, *ValidationRequest) (*ValidationResponse, error)
	ValidateAllocationParameters(context.Context, *ParametersValidationRequest) (*ParametersValidationResponse, error)
	mustEmbedUnimplementedValidatorIPServiceServer()
}

// UnimplementedValidatorIPServiceServer must be embedded to have forward compatible implementations.
type UnimplementedValidatorIPServiceServer struct {
}

func (UnimplementedValidatorIPServiceServer) ValidateAllocation(context.Context, *ValidationRequest) (*ValidationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateAllocation not implemented")
}
func (UnimplementedValidatorIPServiceServer) ValidateAllocationParameters(context.Context, *ParametersValidationRequest) (*ParametersValidationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ValidateAllocationParameters not implemented")
}
func (UnimplementedValidatorIPServiceServer) mustEmbedUnimplementedValidatorIPServiceServer() {}

// UnsafeValidatorIPServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ValidatorIPServiceServer will
// result in compilation errors.
type UnsafeValidatorIPServiceServer interface {
	mustEmbedUnimplementedValidatorIPServiceServer()
}

func RegisterValidatorIPServiceServer(s grpc.ServiceRegistrar, srv ValidatorIPServiceServer) {
	s.RegisterService(&ValidatorIPService_ServiceDesc, srv)
}

func _ValidatorIPService_ValidateAllocation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ValidationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ValidatorIPServiceServer).ValidateAllocation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.ValidatorIPService/ValidateAllocation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ValidatorIPServiceServer).ValidateAllocation(ctx, req.(*ValidationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ValidatorIPService_ValidateAllocationParameters_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ParametersValidationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ValidatorIPServiceServer).ValidateAllocationParameters(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.ValidatorIPService/ValidateAllocationParameters",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ValidatorIPServiceServer).ValidateAllocationParameters(ctx, req.(*ParametersValidationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ValidatorIPService_ServiceDesc is the grpc.ServiceDesc for ValidatorIPService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ValidatorIPService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.ValidatorIPService",
	HandlerType: (*ValidatorIPServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ValidateAllocation",
			Handler:    _ValidatorIPService_ValidateAllocation_Handler,
		},
		{
			MethodName: "ValidateAllocationParameters",
			Handler:    _ValidatorIPService_ValidateAllocationParameters_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "netflix/titus/titus_vpc_api.proto",
}

// IPServiceClient is the client API for IPService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type IPServiceClient interface {
	AllocateStaticIPAddress(ctx context.Context, in *AllocateStaticIPAddressRequest, opts ...grpc.CallOption) (*AllocateStaticIPAddressResponse, error)
	SetPool(ctx context.Context, in *SetPoolRequest, opts ...grpc.CallOption) (*SetPoolResponse, error)
	CreateTag(ctx context.Context, in *CreateTagRequest, opts ...grpc.CallOption) (*CreateTagResponse, error)
	DeleteTag(ctx context.Context, in *CreateTagRequest, opts ...grpc.CallOption) (*DeleteTagResponse, error)
	UpdateTag(ctx context.Context, in *UpdateTagRequest, opts ...grpc.CallOption) (*UpdateTagResponse, error)
	GetStaticIPAddress(ctx context.Context, in *GetStaticIPAddressRequest, opts ...grpc.CallOption) (*GetStaticIPAddressResponse, error)
	GetStaticIPAddresses(ctx context.Context, in *GetStaticIPAddressesRequest, opts ...grpc.CallOption) (*GetStaticIPAddressesResponse, error)
}

type iPServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewIPServiceClient(cc grpc.ClientConnInterface) IPServiceClient {
	return &iPServiceClient{cc}
}

func (c *iPServiceClient) AllocateStaticIPAddress(ctx context.Context, in *AllocateStaticIPAddressRequest, opts ...grpc.CallOption) (*AllocateStaticIPAddressResponse, error) {
	out := new(AllocateStaticIPAddressResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/AllocateStaticIPAddress", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) SetPool(ctx context.Context, in *SetPoolRequest, opts ...grpc.CallOption) (*SetPoolResponse, error) {
	out := new(SetPoolResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/SetPool", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) CreateTag(ctx context.Context, in *CreateTagRequest, opts ...grpc.CallOption) (*CreateTagResponse, error) {
	out := new(CreateTagResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/CreateTag", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) DeleteTag(ctx context.Context, in *CreateTagRequest, opts ...grpc.CallOption) (*DeleteTagResponse, error) {
	out := new(DeleteTagResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/DeleteTag", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) UpdateTag(ctx context.Context, in *UpdateTagRequest, opts ...grpc.CallOption) (*UpdateTagResponse, error) {
	out := new(UpdateTagResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/UpdateTag", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) GetStaticIPAddress(ctx context.Context, in *GetStaticIPAddressRequest, opts ...grpc.CallOption) (*GetStaticIPAddressResponse, error) {
	out := new(GetStaticIPAddressResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/GetStaticIPAddress", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *iPServiceClient) GetStaticIPAddresses(ctx context.Context, in *GetStaticIPAddressesRequest, opts ...grpc.CallOption) (*GetStaticIPAddressesResponse, error) {
	out := new(GetStaticIPAddressesResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.IPService/GetStaticIPAddresses", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IPServiceServer is the server API for IPService service.
// All implementations must embed UnimplementedIPServiceServer
// for forward compatibility
type IPServiceServer interface {
	AllocateStaticIPAddress(context.Context, *AllocateStaticIPAddressRequest) (*AllocateStaticIPAddressResponse, error)
	SetPool(context.Context, *SetPoolRequest) (*SetPoolResponse, error)
	CreateTag(context.Context, *CreateTagRequest) (*CreateTagResponse, error)
	DeleteTag(context.Context, *CreateTagRequest) (*DeleteTagResponse, error)
	UpdateTag(context.Context, *UpdateTagRequest) (*UpdateTagResponse, error)
	GetStaticIPAddress(context.Context, *GetStaticIPAddressRequest) (*GetStaticIPAddressResponse, error)
	GetStaticIPAddresses(context.Context, *GetStaticIPAddressesRequest) (*GetStaticIPAddressesResponse, error)
	mustEmbedUnimplementedIPServiceServer()
}

// UnimplementedIPServiceServer must be embedded to have forward compatible implementations.
type UnimplementedIPServiceServer struct {
}

func (UnimplementedIPServiceServer) AllocateStaticIPAddress(context.Context, *AllocateStaticIPAddressRequest) (*AllocateStaticIPAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AllocateStaticIPAddress not implemented")
}
func (UnimplementedIPServiceServer) SetPool(context.Context, *SetPoolRequest) (*SetPoolResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetPool not implemented")
}
func (UnimplementedIPServiceServer) CreateTag(context.Context, *CreateTagRequest) (*CreateTagResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateTag not implemented")
}
func (UnimplementedIPServiceServer) DeleteTag(context.Context, *CreateTagRequest) (*DeleteTagResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteTag not implemented")
}
func (UnimplementedIPServiceServer) UpdateTag(context.Context, *UpdateTagRequest) (*UpdateTagResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateTag not implemented")
}
func (UnimplementedIPServiceServer) GetStaticIPAddress(context.Context, *GetStaticIPAddressRequest) (*GetStaticIPAddressResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStaticIPAddress not implemented")
}
func (UnimplementedIPServiceServer) GetStaticIPAddresses(context.Context, *GetStaticIPAddressesRequest) (*GetStaticIPAddressesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetStaticIPAddresses not implemented")
}
func (UnimplementedIPServiceServer) mustEmbedUnimplementedIPServiceServer() {}

// UnsafeIPServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to IPServiceServer will
// result in compilation errors.
type UnsafeIPServiceServer interface {
	mustEmbedUnimplementedIPServiceServer()
}

func RegisterIPServiceServer(s grpc.ServiceRegistrar, srv IPServiceServer) {
	s.RegisterService(&IPService_ServiceDesc, srv)
}

func _IPService_AllocateStaticIPAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AllocateStaticIPAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).AllocateStaticIPAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/AllocateStaticIPAddress",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).AllocateStaticIPAddress(ctx, req.(*AllocateStaticIPAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_SetPool_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetPoolRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).SetPool(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/SetPool",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).SetPool(ctx, req.(*SetPoolRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_CreateTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTagRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).CreateTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/CreateTag",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).CreateTag(ctx, req.(*CreateTagRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_DeleteTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateTagRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).DeleteTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/DeleteTag",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).DeleteTag(ctx, req.(*CreateTagRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_UpdateTag_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateTagRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).UpdateTag(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/UpdateTag",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).UpdateTag(ctx, req.(*UpdateTagRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_GetStaticIPAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetStaticIPAddressRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).GetStaticIPAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/GetStaticIPAddress",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).GetStaticIPAddress(ctx, req.(*GetStaticIPAddressRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _IPService_GetStaticIPAddresses_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetStaticIPAddressesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(IPServiceServer).GetStaticIPAddresses(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.IPService/GetStaticIPAddresses",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(IPServiceServer).GetStaticIPAddresses(ctx, req.(*GetStaticIPAddressesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// IPService_ServiceDesc is the grpc.ServiceDesc for IPService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var IPService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.IPService",
	HandlerType: (*IPServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AllocateStaticIPAddress",
			Handler:    _IPService_AllocateStaticIPAddress_Handler,
		},
		{
			MethodName: "SetPool",
			Handler:    _IPService_SetPool_Handler,
		},
		{
			MethodName: "CreateTag",
			Handler:    _IPService_CreateTag_Handler,
		},
		{
			MethodName: "DeleteTag",
			Handler:    _IPService_DeleteTag_Handler,
		},
		{
			MethodName: "UpdateTag",
			Handler:    _IPService_UpdateTag_Handler,
		},
		{
			MethodName: "GetStaticIPAddress",
			Handler:    _IPService_GetStaticIPAddress_Handler,
		},
		{
			MethodName: "GetStaticIPAddresses",
			Handler:    _IPService_GetStaticIPAddresses_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "netflix/titus/titus_vpc_api.proto",
}

// TitusAgentVPCInformationServiceClient is the client API for TitusAgentVPCInformationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TitusAgentVPCInformationServiceClient interface {
	ListBranchToTrunkENIMapping(ctx context.Context, in *GetBranchToTrunkENIMappingRequest, opts ...grpc.CallOption) (*GetBranchToTrunkENIMappingResponse, error)
}

type titusAgentVPCInformationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTitusAgentVPCInformationServiceClient(cc grpc.ClientConnInterface) TitusAgentVPCInformationServiceClient {
	return &titusAgentVPCInformationServiceClient{cc}
}

func (c *titusAgentVPCInformationServiceClient) ListBranchToTrunkENIMapping(ctx context.Context, in *GetBranchToTrunkENIMappingRequest, opts ...grpc.CallOption) (*GetBranchToTrunkENIMappingResponse, error) {
	out := new(GetBranchToTrunkENIMappingResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.TitusAgentVPCInformationService/ListBranchToTrunkENIMapping", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TitusAgentVPCInformationServiceServer is the server API for TitusAgentVPCInformationService service.
// All implementations must embed UnimplementedTitusAgentVPCInformationServiceServer
// for forward compatibility
type TitusAgentVPCInformationServiceServer interface {
	ListBranchToTrunkENIMapping(context.Context, *GetBranchToTrunkENIMappingRequest) (*GetBranchToTrunkENIMappingResponse, error)
	mustEmbedUnimplementedTitusAgentVPCInformationServiceServer()
}

// UnimplementedTitusAgentVPCInformationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTitusAgentVPCInformationServiceServer struct {
}

func (UnimplementedTitusAgentVPCInformationServiceServer) ListBranchToTrunkENIMapping(context.Context, *GetBranchToTrunkENIMappingRequest) (*GetBranchToTrunkENIMappingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListBranchToTrunkENIMapping not implemented")
}
func (UnimplementedTitusAgentVPCInformationServiceServer) mustEmbedUnimplementedTitusAgentVPCInformationServiceServer() {
}

// UnsafeTitusAgentVPCInformationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TitusAgentVPCInformationServiceServer will
// result in compilation errors.
type UnsafeTitusAgentVPCInformationServiceServer interface {
	mustEmbedUnimplementedTitusAgentVPCInformationServiceServer()
}

func RegisterTitusAgentVPCInformationServiceServer(s grpc.ServiceRegistrar, srv TitusAgentVPCInformationServiceServer) {
	s.RegisterService(&TitusAgentVPCInformationService_ServiceDesc, srv)
}

func _TitusAgentVPCInformationService_ListBranchToTrunkENIMapping_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetBranchToTrunkENIMappingRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TitusAgentVPCInformationServiceServer).ListBranchToTrunkENIMapping(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.TitusAgentVPCInformationService/ListBranchToTrunkENIMapping",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TitusAgentVPCInformationServiceServer).ListBranchToTrunkENIMapping(ctx, req.(*GetBranchToTrunkENIMappingRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TitusAgentVPCInformationService_ServiceDesc is the grpc.ServiceDesc for TitusAgentVPCInformationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TitusAgentVPCInformationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.TitusAgentVPCInformationService",
	HandlerType: (*TitusAgentVPCInformationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListBranchToTrunkENIMapping",
			Handler:    _TitusAgentVPCInformationService_ListBranchToTrunkENIMapping_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "netflix/titus/titus_vpc_api.proto",
}

// TitusAgentSecurityGroupServiceClient is the client API for TitusAgentSecurityGroupService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TitusAgentSecurityGroupServiceClient interface {
	ResetSecurityGroup(ctx context.Context, in *ResetSecurityGroupRequest, opts ...grpc.CallOption) (*ResetSecurityGroupResponse, error)
}

type titusAgentSecurityGroupServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTitusAgentSecurityGroupServiceClient(cc grpc.ClientConnInterface) TitusAgentSecurityGroupServiceClient {
	return &titusAgentSecurityGroupServiceClient{cc}
}

func (c *titusAgentSecurityGroupServiceClient) ResetSecurityGroup(ctx context.Context, in *ResetSecurityGroupRequest, opts ...grpc.CallOption) (*ResetSecurityGroupResponse, error) {
	out := new(ResetSecurityGroupResponse)
	err := c.cc.Invoke(ctx, "/com.netflix.titus.TitusAgentSecurityGroupService/ResetSecurityGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TitusAgentSecurityGroupServiceServer is the server API for TitusAgentSecurityGroupService service.
// All implementations must embed UnimplementedTitusAgentSecurityGroupServiceServer
// for forward compatibility
type TitusAgentSecurityGroupServiceServer interface {
	ResetSecurityGroup(context.Context, *ResetSecurityGroupRequest) (*ResetSecurityGroupResponse, error)
	mustEmbedUnimplementedTitusAgentSecurityGroupServiceServer()
}

// UnimplementedTitusAgentSecurityGroupServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTitusAgentSecurityGroupServiceServer struct {
}

func (UnimplementedTitusAgentSecurityGroupServiceServer) ResetSecurityGroup(context.Context, *ResetSecurityGroupRequest) (*ResetSecurityGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ResetSecurityGroup not implemented")
}
func (UnimplementedTitusAgentSecurityGroupServiceServer) mustEmbedUnimplementedTitusAgentSecurityGroupServiceServer() {
}

// UnsafeTitusAgentSecurityGroupServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TitusAgentSecurityGroupServiceServer will
// result in compilation errors.
type UnsafeTitusAgentSecurityGroupServiceServer interface {
	mustEmbedUnimplementedTitusAgentSecurityGroupServiceServer()
}

func RegisterTitusAgentSecurityGroupServiceServer(s grpc.ServiceRegistrar, srv TitusAgentSecurityGroupServiceServer) {
	s.RegisterService(&TitusAgentSecurityGroupService_ServiceDesc, srv)
}

func _TitusAgentSecurityGroupService_ResetSecurityGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ResetSecurityGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TitusAgentSecurityGroupServiceServer).ResetSecurityGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/com.netflix.titus.TitusAgentSecurityGroupService/ResetSecurityGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TitusAgentSecurityGroupServiceServer).ResetSecurityGroup(ctx, req.(*ResetSecurityGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TitusAgentSecurityGroupService_ServiceDesc is the grpc.ServiceDesc for TitusAgentSecurityGroupService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TitusAgentSecurityGroupService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.netflix.titus.TitusAgentSecurityGroupService",
	HandlerType: (*TitusAgentSecurityGroupServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ResetSecurityGroup",
			Handler:    _TitusAgentSecurityGroupService_ResetSecurityGroup_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "netflix/titus/titus_vpc_api.proto",
}
