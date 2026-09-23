package ui

// DashboardLayout keeps all dashboard panel dimensions in one place.
type DashboardLayout struct {
	Width, Height int

	HeaderHeight int
	StatusHeight int
	LogHeight    int
	FooterHeight int

	BodyHeight int

	MapWidth  int
	MapHeight int

	RightWidth int

	TopRowHeight int
	BottomHeight int
}

type LayoutEngine struct {
	Width, Height int
}

func NewLayoutEngine(w, h int) LayoutEngine {
	return LayoutEngine{Width: w, Height: h}
}

func (le LayoutEngine) Calculate() DashboardLayout {
	w, h := le.Width, le.Height

	const (
		minLogHeight  = 7
		maxLogHeight  = 14
		minBodyHeight = 10
		minMapWidth   = 14
		headerHeight  = 7
		statusHeight  = 1
		mapAspectW    = 2
		minTopRow     = 10
		minBottom     = 6
	)

	logHeight := h / 6
	if logHeight < minLogHeight {
		logHeight = minLogHeight
	}
	if logHeight > maxLogHeight {
		logHeight = maxLogHeight
	}

	footerHeight := logHeight + statusHeight
	bodyHeight := h - headerHeight - footerHeight
	if bodyHeight < minBodyHeight {
		bodyHeight = minBodyHeight
	}

	topRowHeight := bodyHeight * 65 / 100
	if topRowHeight > bodyHeight-minBottom {
		topRowHeight = bodyHeight - minBottom
	}
	if topRowHeight < minTopRow {
		topRowHeight = minTopRow
	}

	bottomHeight := bodyHeight - topRowHeight
	if bottomHeight < minBottom {
		bottomHeight = minBottom
		topRowHeight = bodyHeight - bottomHeight
	}

	mapWidth := topRowHeight * mapAspectW
	if mapWidth < 24 {
		mapWidth = 24
	}

	if w >= 72 && mapWidth > w-32 {
		mapWidth = w - 32
	} else if w >= 48 && mapWidth > w-24 {
		mapWidth = w - 24
	} else if mapWidth > w-18 {
		mapWidth = w - 18
	}
	if mapWidth >= w {
		mapWidth = w - 1
	}
	if mapWidth < minMapWidth {
		mapWidth = minMapWidth
	}

	rightWidth := w - mapWidth
	if rightWidth < 1 {
		rightWidth = 1
	}

	return DashboardLayout{
		Width:        w,
		Height:       h,
		HeaderHeight: headerHeight,
		StatusHeight: statusHeight,
		LogHeight:    logHeight,
		FooterHeight: footerHeight,
		BodyHeight:   bodyHeight,
		MapWidth:     mapWidth,
		MapHeight:    topRowHeight,
		RightWidth:   rightWidth,
		TopRowHeight: topRowHeight,
		BottomHeight: bottomHeight,
	}
}
