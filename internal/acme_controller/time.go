package acme_controller

import "time"

func timeMarshalDB(t time.Time) int64 {
	return t.Unix()
}

func timeUnmarshalDB(t int64) time.Time {
	return time.Unix(t, 0)
}
