package main

import (
	"github.com/IBM/simrun/pack"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"

	"github.com/confluentinc/simrun-stratus-pack/adapter"
	_ "github.com/confluentinc/simrun-stratus-pack/techniques"
)

// Version is set via ldflags at build time.
var Version = "dev"

func main() {
	pack.SetPackInfo("stratus", Version, "3.0.0")

	for _, technique := range stratus.GetRegistry().ListAttackTechniques() {
		pack.Register(adapter.AdaptTechnique(technique))
	}

	pack.Run()
}
