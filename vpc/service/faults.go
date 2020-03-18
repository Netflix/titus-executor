package service

import "context"

type faultKey interface {
}

func newFaultKey() faultKey {
	return &struct {
		int
	}{}
}

var (
	// Runs in associateNetworkInterface between startAssociation and finishAssociation
	associateFaultKey = newFaultKey()
	// Runs in disassociateNetworkInterface between startDisassociation and finishDisassociation
	disassociateFaultKey = newFaultKey()

	beforeSelectedDisassociationFaultKey = newFaultKey()
	afterSelectedDisassociationFaultKey  = newFaultKey()

	afterAttachFaultKey = newFaultKey()
)

type fault struct {
	callback func(context.Context, ...interface{}) error
}

func (f *fault) call(ctx context.Context, opts ...interface{}) error {
	if f == nil {
		return nil
	}
	return f.callback(ctx, opts...)
}

func lookupFault(ctx context.Context, key faultKey) *fault {
	val := ctx.Value(key)
	f, ok := val.(*fault)
	if ok {
		return f
	}
	return nil
}

func registerFault(ctx context.Context, key faultKey, cb func(context.Context, ...interface{}) error) context.Context {
	return context.WithValue(ctx, key, &fault{callback: cb})
}
