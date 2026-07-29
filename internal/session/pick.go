package session

// Candidate is one session of the current user, reduced to the fields the
// selection logic needs. Kept free of D-Bus types so it is unit-testable.
type Candidate struct {
	ID        string
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

// pickCandidate chooses the session the agent tracks: an active graphical
// one if available, then any active, then any graphical, then the first.
func pickCandidate(cands []Candidate) (Candidate, bool) {
	best, bestScore := -1, -1
	for i, c := range cands {
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
