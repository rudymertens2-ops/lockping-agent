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
				{ID: "1", Active: true, Graphical: false},
				{ID: "2", Active: true, Graphical: true},
			},
			wantID: "2", wantOK: true,
		},
		{
			name: "prefers active tty over inactive graphical",
			cands: []Candidate{
				{ID: "3", Active: false, Graphical: true},
				{ID: "1", Active: true, Graphical: false},
			},
			wantID: "1", wantOK: true,
		},
		{
			name: "prefers inactive graphical over inactive tty",
			cands: []Candidate{
				{ID: "1", Active: false, Graphical: false},
				{ID: "3", Active: false, Graphical: true},
			},
			wantID: "3", wantOK: true,
		},
		{
			name:   "single session wins by default",
			cands:  []Candidate{{ID: "9"}},
			wantID: "9", wantOK: true,
		},
		{
			name: "first wins on equal score",
			cands: []Candidate{
				{ID: "a", Active: true, Graphical: true},
				{ID: "b", Active: true, Graphical: true},
			},
			wantID: "a", wantOK: true,
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
