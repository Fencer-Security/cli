package operations

import (
	"net/url"
	"strconv"

	"fencer/cli/api"
)

func addEach[E ~string](q url.Values, key string, values []E) {
	for _, v := range values {
		if s := string(v); s != "" {
			q.Add(key, s)
		}
	}
}

func setIf(q url.Values, key, value string) {
	if value != "" {
		q.Set(key, value)
	}
}

func setBoolPtr(q url.Values, key string, b *bool) {
	if b != nil {
		q.Set(key, strconv.FormatBool(*b))
	}
}

func addSeverityFilters(q url.Values, values []string) error {
	for _, v := range values {
		code, err := SeverityCode(v)
		if err != nil {
			return err
		}
		q.Add("severity", code)
	}
	return nil
}

func addAssigneeFilters(client *api.Client, orgSlug string, q url.Values, values []string) error {
	for _, v := range values {
		id, err := ResolveAssigneeFilter(client, orgSlug, v)
		if err != nil {
			return err
		}
		q.Add("assignee", id)
	}
	return nil
}
