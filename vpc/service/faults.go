package service

import "context"

type faultKey *struct{}

var (
	associateFaultKey    faultKey = &struct{}{}
	disassociateFaultKey faultKey = &struct{}{}
)

type fault struct {
	callback func(context.Context) error
}

func (f *fault) call(ctx context.Context) error {
	if f == nil {
		return nil
	}
	return f.callback(ctx)
}

func lookupFault(ctx context.Context, key faultKey) *fault {
	val := ctx.Value(key)
	f, ok := val.(*fault)
	if ok {
		return f
	}
	return nil
}

func registerFault(ctx context.Context, key faultKey, cb func(context.Context) error) context.Context {
	return context.WithValue(ctx, key, &fault{callback: cb})
}
