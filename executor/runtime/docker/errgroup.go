package docker

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type group struct {
	ctx   context.Context
	group *errgroup.Group
}

func groupWithContext(ctx context.Context) *group {
	g := &group{}
	g.group, g.ctx = errgroup.WithContext(ctx)
	return g
}

func (g *group) Go(f func(ctx context.Context) error) {
	g.group.Go(func() error {
		return f(g.ctx)
	})
}

func (g *group) Wait() error {
	return g.group.Wait()
}
