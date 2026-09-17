// Command u2f is a one-off utility to strip the legacy U2F attributes
// (encryptedAppId, encryptedKeyHandle, encryptedPublicKey) from every record
// in the WebAuthn DynamoDB table. Records that have none of these attributes
// are left untouched. However, it is worth noting that non-U2F records contain
// these attributes but only have empty content in them.
//
// By default, it runs in dry-run mode and only reports what it would change.
// Pass -yes to actually write the changes.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/kelseyhightower/envconfig"
)

// legacyU2FAttrs are the attribute names to be removed from every WebAuthn
// table record that has them.
var legacyU2FAttrs = []string{"encryptedAppId", "encryptedKeyHandle", "encryptedPublicKey"}

// webAuthnTablePK is the primary key attribute name in the WebAuthn table (mirrors mfa.WebAuthnTablePK).
const webAuthnTablePK = "uuid"

type envVars struct {
	WebauthnTable    string `required:"true" split_words:"true"`
	AwsEndpoint      string `default:"" split_words:"true"`
	AwsDefaultRegion string `default:"" split_words:"true"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	yes := flag.Bool("yes", false, "actually write changes (default is dry-run, which only reports what would change)")
	flag.Parse()

	var env envVars
	if err := envconfig.Process("", &env); err != nil {
		slog.Error("error loading env vars", "error", err)
		os.Exit(1)
	}

	cfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion(env.AwsDefaultRegion),
		awsconfig.WithBaseEndpoint(env.AwsEndpoint),
	)
	if err != nil {
		slog.Error("failed to load AWS config", "error", err)
		os.Exit(1)
	}

	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.EndpointOptions.DisableHTTPS = cfg.BaseEndpoint != nil
	})

	if !*yes {
		slog.Info("running in dry-run mode; pass -yes to write changes")
	}

	if err := run(context.Background(), client, env.WebauthnTable, *yes); err != nil {
		slog.Error("run failed", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, client *dynamodb.Client, table string, yes bool) error {
	var (
		scanned int
		matched int
		updated int
	)

	var lastKey map[string]types.AttributeValue

	for {
		out, err := client.Scan(ctx, &dynamodb.ScanInput{
			TableName:         aws.String(table),
			ExclusiveStartKey: lastKey,
		})
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		for _, item := range out.Items {
			scanned++

			pk, ok := item[webAuthnTablePK]
			if !ok {
				slog.Warn("record missing primary key attribute, skipping", "attr", webAuthnTablePK)
				continue
			}

			var present []string
			for _, attr := range legacyU2FAttrs {
				if _, ok := item[attr]; ok {
					present = append(present, attr)
				}
			}

			if len(present) == 0 {
				continue
			}

			matched++

			id := attrValueToString(pk)
			slog.Info("found attributes", "uuid", id, "attrs", present)

			if !yes {
				continue
			}

			if err := removeAttrs(ctx, client, table, pk, present); err != nil {
				return fmt.Errorf("failed to update record %s: %w", id, err)
			}
			updated++
		}

		if out.LastEvaluatedKey == nil {
			break
		}
		lastKey = out.LastEvaluatedKey
	}

	slog.Info("done", "scanned", scanned, "matched", matched, "updated", updated, "dryRun", !yes)
	return nil
}

func removeAttrs(ctx context.Context, client *dynamodb.Client, table string, pk types.AttributeValue, attrs []string) error {
	names := make(map[string]string, len(attrs))
	var expr strings.Builder
	for i, attr := range attrs {
		placeholder := fmt.Sprintf("#a%d", i)
		names[placeholder] = attr
		if i > 0 {
			expr.WriteString(", ")
		}
		expr.WriteString(placeholder)
	}

	_, err := client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(table),
		Key: map[string]types.AttributeValue{
			webAuthnTablePK: pk,
		},
		UpdateExpression:         aws.String("REMOVE " + expr.String()),
		ExpressionAttributeNames: names,
	})
	return err
}

func attrValueToString(av types.AttributeValue) string {
	if s, ok := av.(*types.AttributeValueMemberS); ok {
		return s.Value
	}
	return fmt.Sprintf("%v", av)
}
