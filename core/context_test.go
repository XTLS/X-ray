package core_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/core"
	_ "unsafe"
)

func TestFromContextPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expect panic, but nil")
		}
	}()

	MustFromContext(context.Background())
}

//go:linkname mustToContextForced github.com/v2fly/v2ray-core/v4.mustToContext
func mustToContextForced(ctx context.Context, v *Instance) context.Context

func TestToContextPanic(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("expect panic, but nil")
		}
	}()

	mustToContextForced(context.Background(), &Instance{})
}
