package session

import "testing"

func TestIsGraphical(t *testing.T) {
	cases := map[string]bool{
		"x11": true, "wayland": true, "mir": true,
		"tty": false, "unspecified": false, "": false,
	}
	for typ, want := range cases {
		if got := isGraphical(typ); got != want {
			t.Errorf("isGraphical(%q) = %v, want %v", typ, got, want)
		}
	}
}

// user is a shorthand for a lockable candidate in the tests below.
func user(id string, active, graphical bool) Candidate {
	return Candidate{ID: id, Class: "user", Active: active, Graphical: graphical}
}

func TestPickCandidate(t *testing.T) {
	tests := []struct {
		name   string
		cands  []Candidate
		wantID string
		wantOK bool
	}{
		{name: "empty list", cands: nil, wantOK: false},
		{
			name: "prefers active graphical over active tty",
			cands: []Candidate{
				user("1", true, false),
				user("2", true, true),
			},
			wantID: "2", wantOK: true,
		},
		{
			name: "prefers active tty over inactive graphical",
			cands: []Candidate{
				user("3", false, true),
				user("1", true, false),
			},
			wantID: "1", wantOK: true,
		},
		{
			name: "prefers inactive graphical over inactive tty",
			cands: []Candidate{
				user("1", false, false),
				user("3", false, true),
			},
			wantID: "3", wantOK: true,
		},
		{
			name:   "single session wins by default",
			cands:  []Candidate{user("9", false, false)},
			wantID: "9", wantOK: true,
		},
		{
			name: "first wins on equal score",
			cands: []Candidate{
				user("a", true, true),
				user("b", true, true),
			},
			wantID: "a", wantOK: true,
		},
		{
			name: "skips the user-manager session even when active",
			cands: []Candidate{
				{ID: "manager", Class: "manager", Active: true, Graphical: false},
				user("desktop", true, true),
			},
			wantID: "desktop", wantOK: true,
		},
		{
			name: "no lockable session when only the manager exists",
			cands: []Candidate{
				{ID: "manager", Class: "manager", Active: true, Graphical: false},
			},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := pickCandidate(tt.cands)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.ID != tt.wantID {
				t.Errorf("picked %q, want %q", got.ID, tt.wantID)
			}
		})
	}
}
