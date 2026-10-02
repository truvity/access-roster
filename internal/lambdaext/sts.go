package lambdaext

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/truvity/access-roster/tokens"
)

// STSAPI is the one STS call this uses.
type STSAPI interface {
	GetWebIdentityToken(ctx context.Context, in *sts.GetWebIdentityTokenInput, opts ...func(*sts.Options)) (*sts.GetWebIdentityTokenOutput, error)
}

// NewSTS builds a regional STS client from the standard credential chain,
// which inside a Lambda extension is the function role's environment
// credentials. AWS_ENDPOINT_URL_STS, when set, overrides the endpoint.
func NewSTS(ctx context.Context) (STSAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load the AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("AWS_REGION is not set; GetWebIdentityToken needs a regional STS endpoint")
	}
	return sts.NewFromConfig(cfg), nil
}

// SubjectFunc returns the function that asks STS for an identity token.
func SubjectFunc(api STSAPI, c Config) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		out, err := api.GetWebIdentityToken(ctx, &sts.GetWebIdentityTokenInput{
			Audience:         []string{c.Audience},
			SigningAlgorithm: aws.String(c.Algorithm),
			DurationSeconds:  aws.Int32(c.Duration),
		})
		if err != nil {
			return "", fmt.Errorf("sts:GetWebIdentityToken: %w", err)
		}
		if aws.ToString(out.WebIdentityToken) == "" {
			return "", errors.New("sts:GetWebIdentityToken returned no token")
		}
		return aws.ToString(out.WebIdentityToken), nil
	}
}

// ExchangeFunc returns the function that trades the identity token at the
// issuer (RFC 8693) for an access token audienced at the OTLP endpoint.
func ExchangeFunc(c Config, client *http.Client) func(context.Context, string) (string, time.Duration, error) {
	ex := &tokens.Exchanger{Issuer: c.Issuer, ClientID: c.OTLPAudience, Client: client}
	return func(ctx context.Context, subject string) (string, time.Duration, error) {
		tok, err := ex.Exchange(ctx, subject, tokens.TypeJWT, c.OTLPAudience)
		if err != nil {
			return "", 0, err
		}
		return tok.AccessToken, time.Until(tok.Expires), nil
	}
}
