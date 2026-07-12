package importer

import (
	"context"
	"encoding/json"
	"time"

	"github.com/cortalabs/cortasentry/internal/discovery"
	"github.com/cortalabs/cortasentry/internal/domain"
	"github.com/cortalabs/cortasentry/internal/findings"
	"github.com/cortalabs/cortasentry/internal/storage/sqlite"
)

// PipelineSink converts imported observations into the same derived state as
// locally collected observations. The source record remains immutable and the
// conclusions can be recalculated later from that record.
type PipelineSink struct {
	Scanner    *discovery.Scanner
	Store      *sqlite.Store
	Advisories *findings.Engine
}

func (s PipelineSink) AddObservation(ctx context.Context, observation *domain.Observation) error {
	result, err := s.Scanner.IngestObservations(ctx, []domain.Observation{*observation}, "")
	if err != nil {
		return err
	}
	for _, assetID := range result.AssetIDs {
		asset, err := s.Store.GetAsset(ctx, assetID)
		if err != nil {
			return err
		}
		for _, finding := range s.Advisories.Evaluate(asset) {
			created, err := s.Store.UpsertFinding(ctx, &finding)
			if err != nil {
				return err
			}
			if created {
				at := time.Now().UTC()
				current, _ := json.Marshal(map[string]any{"advisory_id": finding.AdvisoryID, "state": finding.State})
				if err := s.Store.AddChange(ctx, domain.ChangeEvent{AssetID: assetID, Type: domain.ChangeNewFinding, Previous: []byte("null"), Current: current, ObservationIDs: []string{observation.ID}, DetectedAt: at, FirstOccurrence: at, LastOccurrence: at}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
