package ui

import (
	_ "embed"
	"strings"
)

//go:embed assets/worldmap.txt
var worldMapRaw string

var worldMapRows []string

func init() {
	worldMapRows = strings.Split(worldMapRaw, "\n")
	for len(worldMapRows) > 0 && len(strings.TrimSpace(worldMapRows[len(worldMapRows)-1])) == 0 {
		worldMapRows = worldMapRows[:len(worldMapRows)-1]
	}
}
