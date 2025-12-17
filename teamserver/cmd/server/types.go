package server

import (
	"Havoc/pkg/agent"
	"Havoc/pkg/db"
	"Havoc/pkg/packager"
	"Havoc/pkg/profile"
	"Havoc/pkg/service"
	"Havoc/pkg/webhook"
	"time"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type Listener struct {
	Name   string
	Type   int
	Config any
}

type Client struct {
	ClientID      string
	Username      string
	GlobalIP      string
	ClientVersion string
	Connection    *websocket.Conn
	Packager      *packager.Packager
	Authenticated bool
	SessionID     string
	Mutex         sync.Mutex
}

type Users struct {
	Name     string
	Password string
	Hashed   bool
	Online   bool
}

type RoleDefinition struct {
	Name        string
	Permissions map[string]bool
}

type SessionContext struct {
	SessionID string
	User      string
	Workspace string
	ExpiresAt time.Time
}

type serverFlags struct {
	Host string
	Port string

	Profile  string
	Verbose  bool
	Debug    bool
	DebugDev bool
	SendLogs bool
	Default  bool
}

type utilFlags struct {
	NoBanner bool
	Debug    bool
	Verbose  bool

	Test bool

	ListOperators bool
}

type TeamserverFlags struct {
	Server serverFlags
	Util   utilFlags
}

type Endpoint struct {
	Endpoint string
	Function func(ctx *gin.Context)
}

type Teamserver struct {
	Flags      TeamserverFlags
	Profile    *profile.Profile
	Clients    sync.Map // map[string]*Client
	Users      []Users
	UserCache  map[string]*db.User
	EventsList []packager.Package
	Service    *service.Service
	WebHooks   *webhook.WebHook
	DB         *db.DB
	Sessions   sync.Map // map[string]SessionContext

	Workspaces map[string]int64
	Roles      map[string]RoleDefinition

	DefaultWorkspaceID int64

	Server struct {
		Path   string
		Engine *gin.Engine
	}

	Agents    agent.Agents
	Listeners []*Listener
	Endpoints []*Endpoint

	Settings struct {
		Compiler64 string
		Compiler32 string
		Nasm       string
	}
}
