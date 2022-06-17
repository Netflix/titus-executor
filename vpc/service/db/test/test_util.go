package db_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/Netflix/titus-executor/logger"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/lib/pq"
)

type PostgresContainer struct {
	id       string // docker container id
	password string // psql password
	port     string // psql port
}

// Start a postgres container locally for testing.
func StartPostgresContainer(ctx context.Context) (*PostgresContainer, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	const IMAGE string = "postgres"
	r, err := cli.ImagePull(ctx, IMAGE, types.ImagePullOptions{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	_, err = io.Copy(io.Discard, r)
	if err != nil {
		return nil, err
	}

	password, err := randomPassword()
	if err != nil {
		return nil, err
	}

	port, err := randomPort()
	if err != nil {
		return nil, err
	}

	createResp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: IMAGE,
		Env: []string{
			"POSTGRES_DB=pgtest",
			"POSTGRES_PASSWORD=" + password,
			"POSTGRES_USER=pgtest",
		},
		Healthcheck: &container.HealthConfig{
			Test:     []string{"CMD-SHELL", "pg_isready -U pgtest"},
			Interval: time.Second,
			Timeout:  time.Second,
			Retries:  10,
		},
	}, &container.HostConfig{
		PortBindings: nat.PortMap{
			"5432/tcp": []nat.PortBinding{
				{HostPort: port},
			},
		},
	}, nil, "pgtest")
	if err != nil {
		return nil, err
	}
	container := &PostgresContainer{
		id:       createResp.ID,
		password: password,
		port:     port,
	}
	err = cli.ContainerStart(ctx, createResp.ID, types.ContainerStartOptions{})
	if err != nil {
		_ = cli.ContainerRemove(ctx, container.id, types.ContainerRemoveOptions{})
		return nil, err
	}

	done := make(chan bool)
	go func() {
		for {
			resp, err := cli.ContainerInspect(ctx, createResp.ID)
			if err == nil && resp.State.Health.Status == types.Healthy {
				done <- true
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()
	select {
	case <-done:
		logger.G(ctx).Infof("started container %s on port %s", container.id, container.port)
		return container, nil
	case <-time.After(time.Minute):
		err = container.Shutdown(ctx)
		if err != nil {
			logger.G(ctx).Errorf("failed to clean up container: %s", err)
		}
		return nil, errors.New("container health check failed")
	}
}

// Connect to the test DB
func (c *PostgresContainer) Connect(ctx context.Context) (*sql.DB, error) {
	url := fmt.Sprintf("postgres://pgtest:%s@localhost:%s/pgtest?sslmode=disable", c.password, c.port)
	return sql.Open("postgres", url)
}

// Stop and remove the container
func (c *PostgresContainer) Shutdown(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}
	defer cli.Close()
	err = cli.ContainerStop(ctx, c.id, nil)
	if err != nil {
		return err
	}
	return cli.ContainerRemove(ctx, c.id, types.ContainerRemoveOptions{})
}

var passwordChars = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randomPassword() (string, error) {
	b := make([]rune, 32)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordChars))))
		if err != nil {
			return "", err
		}
		b[i] = passwordChars[idx.Int64()]
	}
	return string(b), nil
}

func randomPort() (string, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}

func InsertSubnet(db *sql.DB, subnetID string) error {
	_, err := db.Exec("INSERT INTO subnets(subnet_id) VALUES ($1)", subnetID)
	return err
}

// Insert N subnets with id being subnet-0, subnet-1, ...
func InsertSubnets(db *sql.DB, n int) error {
	for i := 0; i < n; i++ {
		err := InsertSubnet(db, fmt.Sprintf("subnet-%d", i))
		if err != nil {
			return err
		}
	}
	return nil
}

func InsertBranchEni(db *sql.DB, branchEni string, securitGroups []string, mac string) error {
	_, err := db.Exec("INSERT INTO branch_enis(branch_eni, account_id, security_groups, mac) VALUES ($1, $2, $3, $4)",
		branchEni, "dummy_account", pq.Array(securitGroups), mac)
	return err
}

func InsertSecurityGroup(db *sql.DB, groupID string) error {
	_, err := db.Exec("INSERT INTO security_groups(group_id) VALUES ($1)", groupID)
	return err
}

// Insert N branc ENIs with id being eni-0, eni-1, ...
func InsertBranchEnis(db *sql.DB, n int) error {
	for i := 0; i < n; i++ {
		sgID := fmt.Sprintf("sg-%d", i)
		err := InsertSecurityGroup(db, sgID)
		if err != nil {
			return err
		}
		err = InsertBranchEni(db, fmt.Sprintf("eni-%d", i), []string{sgID}, "01:23:45:67:89:ab")
		if err != nil {
			return err
		}
	}
	return nil
}

func InsertBranchEniAttachment(db *sql.DB, branchEni, state string) error {
	_, err := db.Exec("INSERT INTO branch_eni_attachments(branch_eni, state) VALUES ($1, $2)", branchEni, state)
	return err
}

// Insert rows into branch_eni_attachments table for branch ENIs in range ["eni-<start>", "eni-<end>")
func InsertBranchEniAttachments(db *sql.DB, start, end int, state string) error {
	for i := start; i < end; i++ {
		err := InsertBranchEniAttachment(db, fmt.Sprintf("eni-%d", i), state)
		if err != nil {
			return err
		}
	}
	return nil
}

func InsertAssignment(db *sql.DB, assignmentID string) error {
	_, err := db.Exec("INSERT INTO assignments(assignment_id) VALUES ($1)", assignmentID)
	return err
}

func InsertAssignments(db *sql.DB, n int) error {
	for i := 0; i < n; i++ {
		err := InsertAssignment(db, fmt.Sprintf("assignment-%d", i))
		if err != nil {
			return err
		}
	}
	return nil
}
