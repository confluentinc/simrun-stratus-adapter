// Package adapter converts Stratus Red Team attack techniques into simrun pack simulations.
package adapter

import (
	"context"
	"fmt"
	"strings"

	"github.com/IBM/simrun/pack"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/google/uuid"
)

// AdaptTechnique converts a Stratus AttackTechnique to a pack Simulation.
func AdaptTechnique(t *stratus.AttackTechnique) pack.Simulation {
	sim := pack.Simulation{
		ID:          slugFromID(t.ID),
		Name:        t.FriendlyName,
		Description: buildDescription(t),
		MITRE: pack.MITREMapping{
			Tactics:    mapTactics(t.MitreAttackTactics),
			Techniques: []string{},
		},
		Scope:                     normalizeScope(t.Platform),
		IsSlow:                    t.IsSlow,
		RequiresExternalResources: len(t.PrerequisitesTerraformCode) > 0,
		Terraform:                 string(t.PrerequisitesTerraformCode),
	}

	if t.Detonate != nil {
		sim.Detonate = adaptDetonate(t.Detonate)
	}

	if t.Revert != nil {
		sim.Cleanup = adaptCleanup(t.Revert)
	}

	return sim
}

// slugFromID extracts the name segment from a Stratus technique ID.
// "aws.persistence.iam-backdoor-role" → "iam-backdoor-role"
func slugFromID(stratusID string) string {
	parts := strings.Split(stratusID, ".")
	return parts[len(parts)-1]
}

// normalizeScope converts Stratus platform constants to lowercase pack scope strings.
func normalizeScope(p stratus.Platform) string {
	switch p {
	case stratus.AWS:
		return "aws"
	case stratus.GCP:
		return "gcp"
	case stratus.Azure:
		return "azure"
	case stratus.Kubernetes:
		return "kubernetes"
	case stratus.EKS:
		return "eks"
	case stratus.EntraID:
		return "entra-id"
	default:
		return strings.ToLower(string(p))
	}
}

// buildDescription combines the technique's description and detection guidance.
func buildDescription(t *stratus.AttackTechnique) string {
	if t.Detection == "" {
		return t.Description
	}
	return t.Description + "\n\n**Detection:**\n" + t.Detection
}

// adaptDetonate wraps a Stratus Detonate function into a pack DetonateFunc.
func adaptDetonate(detonate func(map[string]string, stratus.CloudProviders) error) pack.DetonateFunc {
	return func(ctx context.Context, input pack.DetonateInput) (*pack.Result, error) {
		providers := buildProviders(input.ExecutionID)

		if err := detonate(input.TerraformOutputs, providers); err != nil {
			return pack.ErrorResult(pack.ErrCodeInternalError, err.Error()), nil
		}

		// Store terraform outputs in indicators so they're available during cleanup.
		// CleanupInput doesn't carry TerraformOutputs directly — they flow through
		// DetonationResult.Indicators instead.
		indicators := map[string]any{}
		for k, v := range input.TerraformOutputs {
			indicators[k] = v
		}

		// Expose the derived UUID so simrun can include it in alert matching.
		// Stratus injects this UUID into cloud provider User-Agent headers,
		// so security alerts reference the UUID rather than the nanoid execution ID.
		indicators["execution_uuid"] = deriveExecutionUUID(input.ExecutionID).String()

		return pack.SuccessResult(indicators), nil
	}
}

// adaptCleanup wraps a Stratus Revert function into a pack CleanupFunc.
func adaptCleanup(revert func(map[string]string, stratus.CloudProviders) error) pack.CleanupFunc {
	return func(ctx context.Context, input pack.CleanupInput) error {
		providers := buildProviders(input.ExecutionID)

		// Recover terraform outputs from the detonation result indicators.
		tfOutputs := extractTerraformOutputs(input.DetonationResult)

		return revert(tfOutputs, providers)
	}
}

// deriveExecutionUUID derives a deterministic UUID v5 from a nanoid execution ID.
// Simrun uses nanoid execution IDs; Stratus expects a UUID.
func deriveExecutionUUID(executionID string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(executionID))
}

// buildProviders constructs a CloudProvidersImpl from an execution ID string.
func buildProviders(executionID string) stratus.CloudProvidersImpl {
	return stratus.CloudProvidersImpl{UniqueCorrelationID: deriveExecutionUUID(executionID)}
}

// extractTerraformOutputs recovers terraform outputs stored in detonation result indicators.
// Returns an empty map (never nil) to avoid panics in Stratus Revert functions that
// index into params directly.
func extractTerraformOutputs(result *pack.Result) map[string]string {
	if result == nil || result.Indicators == nil {
		return make(map[string]string)
	}

	outputs := make(map[string]string, len(result.Indicators))
	for k, v := range result.Indicators {
		switch val := v.(type) {
		case string:
			outputs[k] = val
		case nil:
			outputs[k] = ""
		default:
			outputs[k] = fmt.Sprintf("%v", val)
		}
	}
	return outputs
}
