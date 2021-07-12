package service

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Netflix/titus-executor/api/netflix/titus"
	"github.com/Netflix/titus-executor/logger"
	"github.com/Netflix/titus-executor/vpc/tracehelpers"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus/ctxlogrus"
	"github.com/lib/pq"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/codes"
)

func (vpcService *vpcService) ValidateAllocationParameters(ctx context.Context, req *titus.ParametersValidationRequest) (*titus.ParametersValidationResponse, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctx, span := trace.StartSpan(ctx, "ValidateAllocationParameters")
	defer span.End()
	log := ctxlogrus.Extract(ctx)
	ctx = logger.WithLogger(ctx, log)
	span.AddAttributes(
		trace.StringAttribute("account", req.AccountId),
		trace.StringAttribute("subnet-ids", fmt.Sprintf("%v", req.Subnets)),
		trace.StringAttribute("security-groups", fmt.Sprintf("%v", req.SecurityGroups)),
	)
	tx, err := vpcService.db.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		err = tracehelpers.WithGRPCStatusCode(fmt.Errorf("Could not start database transaction: %w", err), codes.Unknown)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	var validationFailures []*titus.ParametersValidationResponse_ValidationFailure

	row := tx.QueryRow("SELECT count(*) FROM accounts WHERE account_id = $1", req.AccountId)
	var accountsFound int
	err = row.Scan(&accountsFound)
	if err != nil {
		err = fmt.Errorf("Could not scan accounts found count: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	if accountsFound == 0 {
		validationFailures = append(validationFailures, &titus.ParametersValidationResponse_ValidationFailure{
			FailureOneOf: &titus.ParametersValidationResponse_ValidationFailure_AccountIdUnsupported{
				AccountIdUnsupported: &titus.ParametersValidationResponse_AccountIdUnsupported{
					AccountId: req.AccountId,
				},
			},
		})
	}

	rows, err := tx.QueryContext(ctx, `
WITH user_subnets AS (SELECT unnest($1::text[]) AS user_subnet_id)
SELECT user_subnet_id,  vpc_id, account_id, subnet_id FROM user_subnets
LEFT JOIN subnets ON user_subnet_id = subnet_id
`, pq.Array(req.Subnets))

	if err != nil {
		err = fmt.Errorf("Could not fetch subnets: %w", err)
		tracehelpers.SetStatus(err, span)
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	// TODO: Add diversity checking
	for rows.Next() {
		var userSubnetID, vpcID, accountID string
		var subnetID sql.NullString
		err = rows.Scan(&userSubnetID, &vpcID, &accountID, &subnetID)
		if err != nil {
			err = fmt.Errorf("Cannot scan subnets: %w", err)
			tracehelpers.SetStatus(err, span)
			return nil, err
		}

		if !subnetID.Valid {
			validationFailures = append(validationFailures, &titus.ParametersValidationResponse_ValidationFailure{
				FailureOneOf: &titus.ParametersValidationResponse_ValidationFailure_SubnetNotFound{
					SubnetNotFound: &titus.ParametersValidationResponse_SubnetNotFound{
						SubnetId: userSubnetID,
					},
				},
			})
			continue
		}

		if accountID != req.AccountId {
			validationFailures = append(validationFailures, &titus.ParametersValidationResponse_ValidationFailure{
				FailureOneOf: &titus.ParametersValidationResponse_ValidationFailure_SubnetDoesNotMatchAccountId{
					SubnetDoesNotMatchAccountId: &titus.ParametersValidationResponse_SubnetDoesNotMatchAccountId{
						SubnetId: userSubnetID,
					},
				},
			})
		}
	}

	// TODO: Add SG Checking
	return &titus.ParametersValidationResponse{
		ValidationFailures: validationFailures,
	}, nil
}
