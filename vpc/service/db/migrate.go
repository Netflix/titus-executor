package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pkg/errors"

	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/service/db/migrations"
	migrate "github.com/golang-migrate/migrate"
	"github.com/golang-migrate/migrate/database/postgres"
	bindata "github.com/golang-migrate/migrate/source/go_bindata"
	"github.com/sirupsen/logrus"
)

func newMigrator(ctx context.Context, db *sql.DB) (*migrate.Migrate, error) {
	s := bindata.Resource(migrations.AssetNames(),
		func(name string) ([]byte, error) {
			return migrations.Asset(name)
		})

	d, err := bindata.WithInstance(s)
	if err != nil {
		return nil, err
	}

	config := postgres.Config{
		MigrationsTable: "migrations",
	}

	query := db.QueryRowContext(ctx, "SELECT current_database()")
	err = query.Scan(&config.DatabaseName)
	if err != nil {
		return nil, errors.Wrap(err, "Could not select current database")
	}

	driver, err := postgres.WithInstance(db, &config)
	if err != nil {
		return nil, errors.Wrap(err, "Could not setup postgres migration client")
	}
	m, err := migrate.NewWithInstance("go-bindata", d, "postgres", driver)
	if err != nil {
		return nil, errors.Wrap(err, "could not generation migration instance")
	}
	m.Log = &migrateLogger{FieldLogger: logger.G(ctx)}
	return m, nil
}

func NeedsMigration(ctx context.Context, db *sql.DB) (bool, error) {
	m, err := newMigrator(ctx, db)
	if err != nil {
		return false, err
	}
	version, dirty, err := m.Version()
	logger.G(ctx).WithField("version", version).Info("Current version")
	if err == migrate.ErrNilVersion {
		return true, nil
	}
	if dirty {
		return true, fmt.Errorf("Database is dirty at version: %d", version)
	}
	return version < 15, err
}

func Migrate(ctx context.Context, db *sql.DB) error {
	m, err := newMigrator(ctx, db)
	if err != nil {
		return err
	}
	err = m.Up()
	if err != nil {
		return errors.Wrap(err, "Could not perform migrations")
	}

	return nil
}

type migrateLogger struct {
	logrus.FieldLogger
}

func (ml migrateLogger) Verbose() bool {
	return true
}
