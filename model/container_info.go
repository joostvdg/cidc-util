package model

import (
	"fmt"
)

// ContainerInfo
type ContainerInfo struct {
	Name          string   `json:"Name"`
	Description   string   `json:"Description"`
	WebPath       string   `json:"WebPath"`
	WebPort       string   `json:"WebPort"`
	Volumes       []string `json:"Volumes"`
	Ports         []string `json:"Ports"`
	Documentation string   `json:"Documentation"`
	Dependencies  []string `json:"Dependencies"`
	Created       int64    `json:"Created"`
	Image         string   `json:"Image"`
}

// String is the String for ContainerInfo config
func (ci *ContainerInfo) String() string {
	return fmt.Sprintf("[Name=%v, Description=%s, WebPath=%s, WebPort=%v]", ci.Name, ci.Description, ci.WebPath, ci.WebPort)
}
