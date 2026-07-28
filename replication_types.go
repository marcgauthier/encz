package sqliteseal

import (
	"context"
	"crypto/tls"
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
type ReplicationRuntimeOptions struct {
	Credentials        ReplicationCredentialProvider
	MembershipVerifier MembershipVerifier
	IdentityGuardPath  string
	ReadYourWriteKey   []byte
	Logf               func(string, ...any)
}
type LocalNodeConfig struct {
	NodeUUID, NodeName, ReplicationDomain, ListenAddress, CredentialName  string
	AuthMode                                                              ReplicationAuthMode
	SchemaVersion                                                         int64
	MaximumFutureSkew, MaximumOffline, EventRetention, TombstoneRetention time.Duration
}
type ReplicatedTable struct {
	Name                       string
	PrimaryKeyColumns, Columns []string
	AllowExplicitRecreation    bool
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
	ConnectedAt                                     time.Time
	ContiguousCounter, HighestSeenCounter, GapCount int64
}
type ReplicationStatus struct {
	Initialized, Ready, NetworkEnabled                                                   bool
	NodeUUID, IncarnationUUID, Domain, SchemaHash, MembershipHash, BlockedReason         string
	ListenAddress                                                                        string
	SchemaVersion, MembershipEpoch, LastOriginCounter, LastHLCPhysicalUS, LastHLCLogical int64
	Peers                                                                                []ReplicationPeerStatus
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
