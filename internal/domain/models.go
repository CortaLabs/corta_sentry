package domain

import (
	"encoding/json"
	"net/netip"
	"time"
)

type ObservationSource string

const (
	SourceNeighbor         ObservationSource = "neighbor"
	SourceTCPConnect       ObservationSource = "tcp_connect"
	SourceBanner           ObservationSource = "banner"
	SourceHTTP             ObservationSource = "http"
	SourceTLS              ObservationSource = "tls"
	SourceMDNS             ObservationSource = "mdns"
	SourceSSDP             ObservationSource = "ssdp"
	SourceHostConnection   ObservationSource = "host_connection"
	SourceImportedNmap     ObservationSource = "imported_nmap"
	SourceImportedZeek     ObservationSource = "imported_zeek"
	SourceImportedSuricata ObservationSource = "imported_suricata"
	SourceImportedNuclei   ObservationSource = "imported_nuclei"
	SourceManual           ObservationSource = "manual"
)

type Observation struct {
	ID, SensorID, JobID, AssetID string
	ObservedAt, IngestedAt       time.Time
	Source                       ObservationSource
	TargetIP                     netip.Addr
	TargetPort                   int
	Transport, Application       string
	Evidence                     json.RawMessage
	RawDigest, CollectorVersion  string
	PolicyDecisionID             string
	Truncated                    bool
	Provenance                   json.RawMessage
}

type Identifier struct {
	Type, Value, Strength, Provenance, ObservationID string
	FirstSeen, LastSeen                              time.Time
}

type Asset struct {
	ID, DisplayName, Status, DeviceClass, Vendor, ProductFamily, Model, Firmware, OS string
	FirstSeen, LastSeen                                                              time.Time
	IdentificationScore                                                              float64
	Ambiguous                                                                        bool
	Criticality                                                                      string
	Tags                                                                             []string
	Notes                                                                            string
	CurrentAddresses, HistoricalAddresses                                            []string
	Identifiers                                                                      []Identifier
	SupportingObservations, ConflictingObservations                                  []string
}

type ScoreContribution struct {
	Predicate, Source, ObservationID string
	Value                            float64
	Matched                          bool
}
type FingerprintCandidate struct {
	ID, AssetID, RuleID, RuleVersion, DeviceClass, Vendor, ProductFamily, Model, Explanation, EngineVersion string
	Score                                                                                                   float64
	SupportingPredicates, NegativePredicates                                                                []string
	SourceDiversity                                                                                         int
	ObservationIDs                                                                                          []string
	Breakdown                                                                                               []ScoreContribution
	EvaluatedAt                                                                                             time.Time
}

type FindingState string

const (
	FindingPotential        FindingState = "potentially_applicable"
	FindingLikely           FindingState = "likely_applicable"
	FindingVersionConfirmed FindingState = "version_confirmed"
	FindingSafelyValidated  FindingState = "safely_validated"
	FindingRemediated       FindingState = "remediated"
	FindingAcceptedRisk     FindingState = "accepted_risk"
	FindingFalsePositive    FindingState = "false_positive"
)

type Finding struct {
	ID, AssetID, AdvisoryID                              string
	State                                                FindingState
	Severity                                             string
	EvidenceScore                                        float64
	ProductEvidence, VersionEvidence, ValidationEvidence json.RawMessage
	Source, RuleDigest                                   string
	FirstSeen, LastEvaluated                             time.Time
	Remediation, OperatorDisposition                     string
}

type ChangeType string

const (
	ChangeAssetFirstSeen    ChangeType = "asset_first_seen"
	ChangeAssetDisappeared  ChangeType = "asset_disappeared"
	ChangeIPAddress         ChangeType = "ip_address_changed"
	ChangeMAC               ChangeType = "mac_address_changed"
	ChangeNewService        ChangeType = "new_service"
	ChangeRemovedService    ChangeType = "removed_service"
	ChangeHTTPTitle         ChangeType = "http_title_changed"
	ChangeCertificate       ChangeType = "certificate_changed"
	ChangeClassification    ChangeType = "classification_changed"
	ChangeFirmware          ChangeType = "firmware_changed"
	ChangeNewFinding        ChangeType = "new_potential_finding"
	ChangeFindingRemediated ChangeType = "finding_remediated"
)

type ChangeEvent struct {
	ID, AssetID                                 string
	Type                                        ChangeType
	Previous, Current                           json.RawMessage
	ObservationIDs                              []string
	DetectedAt, FirstOccurrence, LastOccurrence time.Time
	Acknowledged                                bool
}

type JobType string

const (
	JobDiscovery           JobType = "discovery_scan"
	JobTargetProbe         JobType = "target_probe"
	JobRuleReevaluation    JobType = "rule_reevaluation"
	JobAssetResolution     JobType = "asset_resolution"
	JobAdvisoryCorrelation JobType = "advisory_correlation"
	JobImport              JobType = "import"
	JobChangeEvaluation    JobType = "change_evaluation"
)

type Job struct {
	ID                             string
	Type                           JobType
	State                          string
	Payload                        json.RawMessage
	AttemptCount                   int
	LeaseOwner                     string
	LeaseExpiresAt                 *time.Time
	CreatedAt                      time.Time
	StartedAt, CompletedAt         *time.Time
	CancelRequested                bool
	ErrorSummary                   string
	ProgressCurrent, ProgressTotal int
	IdempotencyKey                 string
}

type AuditEvent struct {
	ID                                                          string
	At                                                          time.Time
	Actor, Action, ResourceType, ResourceID, Outcome, RequestID string
	Details                                                     json.RawMessage
}

type Event struct {
	Type       string
	At         time.Time
	ResourceID string
	Data       json.RawMessage
}
type EventPublisher interface{ Publish(Event) }
