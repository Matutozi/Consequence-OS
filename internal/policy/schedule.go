package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // embeds the time zone database, so zones load even on minimal images
)

// Schedule is a weekly time window in one time zone. A rule with
// "during: <schedule>" applies only inside the window, and one with
// "outside: <schedule>" only outside it.
//
//	outside:
//	  days: [mon, tue, wed, thu, fri] # optional; all days when left out
//	  hours: "09:00-17:00"            # optional; the whole day when left out
//	  timezone: Africa/Lagos          # required, an IANA zone name
//
// Hours include the start and exclude the end. "22:00-06:00" runs past
// midnight; days are checked against the local date of the call.
type Schedule struct {
	Days     []string `yaml:"days,omitempty"`
	Hours    string   `yaml:"hours,omitempty"`
	Timezone string   `yaml:"timezone"`

	// Filled in by compile.
	loc        *time.Location
	days       [7]bool // indexed by time.Weekday
	start, end int     // minutes since midnight; equal means the whole day
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// compile checks the schedule and parses it for contains.
func (s *Schedule) compile() error {
	if s.Timezone == "" {
		return errors.New("timezone is required, e.g. Africa/Lagos or UTC")
	}
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		return fmt.Errorf("unknown timezone %q", s.Timezone)
	}
	s.loc = loc

	if len(s.Days) == 0 {
		s.days = [7]bool{true, true, true, true, true, true, true}
	}
	for _, d := range s.Days {
		day, ok := dayNames[strings.ToLower(d)]
		if !ok {
			return fmt.Errorf("unknown day %q (want mon, tue, wed, thu, fri, sat or sun)", d)
		}
		s.days[day] = true
	}

	if s.Hours == "" {
		return nil // start == end == 0: the whole day
	}
	from, to, ok := strings.Cut(s.Hours, "-")
	if !ok {
		return fmt.Errorf("hours %q must look like 09:00-17:00", s.Hours)
	}
	if s.start, err = parseClock(from); err == nil {
		s.end, err = parseClock(to)
	}
	if err != nil {
		return fmt.Errorf("hours %q: %w", s.Hours, err)
	}
	if s.start == s.end {
		return fmt.Errorf("hours %q start and end at the same time; leave hours out for the whole day", s.Hours)
	}
	return nil
}

// parseClock turns "09:30" into minutes since midnight.
func parseClock(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%q is not a time like 09:00", s)
	}
	return t.Hour()*60 + t.Minute(), nil
}

// contains reports whether t falls inside the window.
func (s *Schedule) contains(t time.Time) bool {
	local := t.In(s.loc)
	if !s.days[local.Weekday()] {
		return false
	}
	minute := local.Hour()*60 + local.Minute()
	switch {
	case s.start == s.end:
		return true
	case s.start < s.end:
		return minute >= s.start && minute < s.end
	default: // runs past midnight
		return minute >= s.start || minute < s.end
	}
}

func (s *Schedule) String() string {
	days := "every day"
	if len(s.Days) > 0 {
		days = strings.Join(s.Days, ",")
	}
	hours := "all day"
	if s.Hours != "" {
		hours = s.Hours
	}
	return fmt.Sprintf("%s %s %s", days, hours, s.Timezone)
}
