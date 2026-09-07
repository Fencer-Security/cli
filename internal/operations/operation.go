package operations

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"fencer/cli/api"
)

// Safety describes whether an operation changes server state.
type Safety string

const (
	SafetyReadOnly    Safety = "read-only"
	SafetyMutating    Safety = "mutating"
	SafetyDestructive Safety = "destructive"
)

const (
	ScopeAPIRead  = "cli:api:read"
	ScopeAPIWrite = "cli:api:write"
)

// Descriptor is the transport-neutral metadata for a registered operation.
type Descriptor struct {
	Name        string
	Description string
	Safety      Safety
	Idempotent  bool
	Scopes      []string
	Paginated   bool
}

// Operation is a transport-neutral Fencer capability shared by CLI and MCP adapters.
type Operation[Input, Output any] struct {
	Name        string
	Description string
	Safety      Safety
	Idempotent  bool
	Scopes      []string
	run         func(context.Context, *api.Client, Input) (Output, error)
}

// Descriptor returns the public metadata for this operation.
func (o Operation[Input, Output]) Descriptor() Descriptor {
	return Descriptor{
		Name:        o.Name,
		Description: o.Description,
		Safety:      o.Safety,
		Idempotent:  o.Idempotent,
		Scopes:      o.Scopes,
		Paginated:   hasPageInput[Input](),
	}
}

func hasPageInput[I any]() bool {
	t := reflect.TypeFor[I]()
	if t.Kind() != reflect.Struct {
		return false
	}
	_, ok := t.FieldByName("PageInput")
	return ok
}

// IsListName reports whether an operation name is a list operation.
func IsListName(name string) bool {
	return strings.Contains(name, ".list")
}

// Execute invokes the operation with the provided API client.
func (o Operation[Input, Output]) Execute(ctx context.Context, client *api.Client, input Input) (Output, error) {
	if o.run == nil {
		var zero Output
		return zero, fmt.Errorf("operation %q has no implementation", o.Name)
	}
	return o.run(ctx, client, input)
}

var registered []Descriptor

// Register records operation metadata so CLI/MCP parity checks can enumerate it.
func Register[I, O any](op Operation[I, O]) Operation[I, O] {
	registered = append(registered, op.Descriptor())
	return op
}

// All returns a copy of every registered operation descriptor.
func All() []Descriptor {
	out := make([]Descriptor, len(registered))
	copy(out, registered)
	return out
}

// Names returns the registered operation names in registration order.
func Names() []string {
	names := make([]string, len(registered))
	for i, d := range registered {
		names[i] = d.Name
	}
	return names
}
