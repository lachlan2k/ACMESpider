package dtos

import "time"

func TimeMarshalDTO(t time.Time) string {
	return t.Format(time.RFC3339)
}

func TimeUnmarshalDTO(in string) (*time.Time, error) {
	t, err := time.Parse(time.RFC3339, in)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
