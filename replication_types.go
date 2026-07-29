package sqliteseal

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

var (
	ErrReplicationNotInitialized     = errors.New("sqliteseal: replication is not initialized")
	ErrReplicationAlreadyInitialized = errors.New("sqliteseal: replication is already initialized")
	ErrReplicationInvalidConfig      = errors.New("sqliteseal: invalid replication configuration")
	ErrReplicationSchemaUnsupported  = errors.New("sqliteseal: table schema is unsupported by replication protocol v1")
	ErrReplicationSchemaMismatch     = errors.New("sqliteseal: replication schema mismatch")
	ErrReplicationMembershipMismatch = errors.New("sqliteseal: replication membership manifest mismatch")
	ErrReplicationIdentityRollback   = errors.New("sqliteseal: replication identity guard is ahead of the database")
	ErrReplicationPeerNotFound       = errors.New("sqliteseal: replication peer not found")
	ErrReplicationNotReady           = errors.New("sqliteseal: replication is not ready")
	ErrReplicationEventQuarantined   = errors.New("sqliteseal: replication event is quarantined")
	ErrReplicationSnapshotRequired   = errors.New("sqliteseal: replication snapshot is required")
)

type ReplicationAuthMode string

const (
	ReplicationAuthPSK  ReplicationAuthMode = "psk"
	ReplicationAuthMTLS ReplicationAuthMode = "mtls"
)

type ReplicationConnectionRole string

const (
	ReplicationDial   ReplicationConnectionRole = "dial"
	ReplicationAccept ReplicationConnectionRole = "accept"
)

type ReplicationCredentialProvider interface {
	PSK(context.Context, string) ([]byte, error)
	TLSConfig(context.Context, string, bool) (*tls.Config, error)
}
type MembershipVerifier interface {
	VerifyMembership(context.Context, []byte, []byte) error
}
type ReplicationCertificateAuthorizer interface {
	AuthorizeReplicationCertificate(context.Context, string, string, string, *x509.Certificate) error
}
type ReplicationRuntimeOptions struct {
	Credentials           ReplicationCredentialProvider
	MembershipVerifier    MembershipVerifier
	CertificateAuthorizer ReplicationCertificateAuthorizer
	IdentityGuardPath     string
	ReadYourWriteKey      []byte
	Logf                  func(string, ...any)
}
type LocalNodeConfig struct {
	NodeUUID, NodeName, ReplicationDomain, ListenAddress, CredentialName  string
	AuthMode                                                              ReplicationAuthMode
	Level                                                                 int
	SchemaVersion                                                         int64
	MaximumFutureSkew, MaximumOffline, EventRetention, TombstoneRetention time.Duration
}
type ReplicationConstraintPolicy string

const (
	// ReplicationConstraintsReject preserves the protocol-v1 fail-closed behaviour.
	ReplicationConstraintsReject ReplicationConstraintPolicy = ""
	// ReplicationConstraintsManaged enables FK deferral and deterministic unique-value LWW.
	ReplicationConstraintsManaged ReplicationConstraintPolicy = "managed"
)

type ReplicatedTable struct {
	Name                       string
	PrimaryKeyColumns, Columns []string
	AllowExplicitRecreation    bool
	ConstraintPolicy           ReplicationConstraintPolicy
}
type PeerConfig struct {
	NodeUUID, IncarnationUUID, NodeName, Address, CredentialName, NextCredentialName, TLSServerName, TLSConfigName string
	ListenEnabled, Enabled                                                                                         bool
	Role                                                                                                           ReplicationConnectionRole
	AuthMode                                                                                                       ReplicationAuthMode
	ConnectTimeout, HeartbeatInterval, HeartbeatTimeout, ReconnectInitial, ReconnectMaximum                        time.Duration
	MaxCompressedBytes, MaxUncompressedBytes, MaxEventsPerBatch, MaxInflightEvents, MaxInflightBytes               int
}
type MembershipNode struct {
	NodeUUID        string                               `json:"node_uuid"`
	IncarnationUUID string                               `json:"incarnation_uuid"`
	Level           int                                  `json:"level"`
	State           string                               `json:"state"`
	ListenEnabled   bool                                 `json:"listen_enabled"`
	RoleByPeer      map[string]ReplicationConnectionRole `json:"role_by_peer"`
}
type MembershipManifest struct {
	Epoch      int64            `json:"epoch"`
	Domain     string           `json:"domain"`
	Nodes      []MembershipNode `json:"nodes"`
	PolicyHash string           `json:"policy_hash"`
	Signature  []byte           `json:"-"`
}
type ReplicationPeerStatus struct {
	NodeUUID, State, LastError                      string
	Level                                           int
	ConnectedAt                                     time.Time
	ContiguousCounter, HighestSeenCounter, GapCount int64
}
type ReplicationStatus struct {
	Initialized, Ready, NetworkEnabled                                                   bool
	NodeUUID, IncarnationUUID, Domain, SchemaHash, MembershipHash, BlockedReason         string
	ListenAddress                                                                        string
	Level                                                                                int
	SchemaVersion, MembershipEpoch, LastOriginCounter, LastHLCPhysicalUS, LastHLCLogical int64
	Peers                                                                                []ReplicationPeerStatus
	SchemaConflicts                                                                      []ReplicationSchemaConflict
}

type ReplicationSchemaConflict struct {
	TableName, ColumnName string
	DeclaredTypes         []string
	OriginNodeUUIDs       []string
	AuthorityLevel        int
}
type ReplicationConflict struct {
	ChangeUUID, OriginNodeUUID, TableName, RowKeyJSON string
	OriginCounter                                     int64
	State, Reason                                     string
}

type ReplicationMigration struct {
	FromVersion, ToVersion int64
	Statements             []string
	Tables                 []ReplicatedTable
}
type ReplicationSnapshotInfo struct {
	SnapshotUUID, SchemaHash, ContentHash string
	CreatedAt                             time.Time
	SizeBytes                             int64
}

type ReplicationOriginProgress struct {
	OriginNodeUUID     string `json:"origin_node_uuid"`
	ContiguousCounter  int64  `json:"contiguous_counter"`
	HighestSeenCounter int64  `json:"highest_seen_counter"`
	GapCount           int64  `json:"gap_count"`
}

type ReplicationSyncStats struct {
	LocalNodeUUID     string                      `json:"local_node_uuid"`
	LastOriginCounter int64                       `json:"last_origin_counter"`
	PeerCursors       []ReplicationOriginProgress `json:"peer_cursors"`
}
