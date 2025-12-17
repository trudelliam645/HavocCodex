package events

import (
	"time"

	"Havoc/pkg/packager"
)

type audit struct{}

var Audit audit

// Log creates an audit package to broadcast to connected clients.
func (audit) Log(user, action, target string, metadata map[string]any) packager.Package {
	return packager.Package{
		Head: packager.Head{
			Event: packager.Type.Audit.Type,
			Time:  time.Now().Format("02/01/2006 15:04:05"),
		},
		Body: packager.Body{
			SubEvent: packager.Type.Audit.Append,
			Info: map[string]any{
				"User":     user,
				"Action":   action,
				"Target":   target,
				"Metadata": metadata,
			},
		},
	}
}
