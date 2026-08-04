package session

// Candidate is one session of the current user, reduced to the fields the
// selection logic needs. Kept free of D-Bus types so it is unit-testable.
type Candidate struct {
	ID        string
	Class     string
	Active    bool
	Graphical bool
}

// isGraphical reports whether a logind session type belongs to a desktop
// the user can actually lock.
func isGraphical(sessionType string) bool {
	switch sessionType {
	case "x11", "wayland", "mir":
		return true
	}
	return false
}

// isLockable reports whether a session can be locked at all. The systemd
// --user manager registers its own session (Class="manager",
// Type="unspecified") that has no screen and never locks; binding to it is
// the classic bug when the agent starts before the graphical session
// exists. Only real user sessions qualify.
func isLockable(c Candidate) bool {
	return c.Class == "user"
}

// pickCandidate chooses the session the agent tracks. It ignores sessions
// that cannot be locked (e.g. the user-manager session), then prefers an
// active graphical one, then any active, then any graphical, then the first.
func pickCandidate(cands []Candidate) (Candidate, bool) {
	best, bestScore := -1, -1
	for i, c := range cands {
		if !isLockable(c) {
			continue
		}
		score := 0
		if c.Active {
			score += 2
		}
		if c.Graphical {
			score++
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return Candidate{}, false
	}
	return cands[best], true
}
