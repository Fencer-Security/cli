package operations

import (
	"fmt"
	"testing"
)

func TestPageInputNormalizedDefaults(t *testing.T) {
	page, size, err := PageInput{}.Normalized()
	if err != nil {
		t.Fatalf("Normalized: %v", err)
	}
	if page != 1 || size != DefaultPageSize {
		t.Fatalf("got page=%d size=%d", page, size)
	}
}

func TestPageInputNormalizedRejectsInvalid(t *testing.T) {
	if _, _, err := (PageInput{Page: -1}).Normalized(); err == nil {
		t.Fatal("expected error for negative page")
	}
	if _, _, err := (PageInput{PageSize: MaxPageSize + 1}).Normalized(); err == nil {
		t.Fatal("expected error for oversized page_size")
	}
	if _, _, err := (PageInput{PageSize: -5}).Normalized(); err == nil {
		t.Fatal("expected error for negative page_size")
	}
}

func TestCollectAllPagesWalksUntilComplete(t *testing.T) {
	fetched := 0
	got, err := collectAllPages(func(page, pageSize int) (Page[string], error) {
		fetched++
		if pageSize != MaxPageSize {
			t.Fatalf("pageSize = %d, want %d", pageSize, MaxPageSize)
		}
		next := page + 1
		switch page {
		case 1:
			return Page[string]{
				Results:    []string{"a", "b"},
				Pagination: Pagination{Page: 1, PageSize: pageSize, Count: 3, TotalPages: 2, NextPage: &next},
			}, nil
		case 2:
			return Page[string]{
				Results:    []string{"c"},
				Pagination: Pagination{Page: 2, PageSize: pageSize, Count: 3, TotalPages: 2},
			}, nil
		default:
			return Page[string]{}, fmt.Errorf("unexpected page %d", page)
		}
	})
	if err != nil {
		t.Fatalf("collectAllPages: %v", err)
	}
	if fetched != 2 {
		t.Fatalf("fetched %d pages, want 2", fetched)
	}
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("results = %v", got)
	}
}

func TestCollectAllPagesErrorsWhenTruncated(t *testing.T) {
	_, err := collectAllPages(func(page, pageSize int) (Page[string], error) {
		return Page[string]{
			Results:    []string{"a"},
			Pagination: Pagination{Page: 1, PageSize: pageSize, Count: 5, TotalPages: 1},
		}, nil
	})
	if err == nil {
		t.Fatal("expected incomplete list error")
	}
}
