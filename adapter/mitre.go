package adapter

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

// tacticIDMap maps Stratus MITRE ATT&CK tactic enums to tactic ID strings.
var tacticIDMap = map[mitreattack.Tactic]string{
	mitreattack.InitialAccess:       "TA0001",
	mitreattack.Execution:           "TA0002",
	mitreattack.Persistence:         "TA0003",
	mitreattack.PrivilegeEscalation: "TA0004",
	mitreattack.DefenseEvasion:      "TA0005",
	mitreattack.CredentialAccess:    "TA0006",
	mitreattack.Discovery:           "TA0007",
	mitreattack.LateralMovement:     "TA0008",
	mitreattack.Collection:          "TA0009",
	mitreattack.Exfiltration:        "TA0010",
	mitreattack.Impact:              "TA0040",
}

// mapTactics converts Stratus MITRE tactic enums to tactic ID strings.
func mapTactics(tactics []mitreattack.Tactic) []string {
	ids := make([]string, 0, len(tactics))
	for _, tactic := range tactics {
		if id, ok := tacticIDMap[tactic]; ok {
			ids = append(ids, id)
		}
	}
	return ids
}
