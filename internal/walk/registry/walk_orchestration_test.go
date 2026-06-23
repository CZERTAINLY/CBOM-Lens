package registry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	registry "github.com/CZERTAINLY/CBOM-lens/internal/walk/registry"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk/registry/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// openCall records each (hive, key, access) passed to the fake opener.
type openCall struct {
	hive   string
	key    string
	access uint32
}

func TestSelectViews_singleByDefault(t *testing.T) {
	views := registry.SelectViews(model.Registry{}, 0xAA, 0xBB)
	require.Len(t, views, 1)
}

func TestSelectViews_dualWhenWOW64(t *testing.T) {
	views := registry.SelectViews(model.Registry{WOW64: true}, 0xAA, 0xBB)
	require.Len(t, views, 2)
}

func TestWalkAll_singleView_opensEachPathOnce(t *testing.T) {
	ctrl := gomock.NewController(t)
	var calls []openCall
	open := func(hive, key string, access uint32) (registry.RegistryKey, error) {
		calls = append(calls, openCall{hive, key, access})
		k := mock.NewMockRegistryKey(ctrl)
		k.EXPECT().ReadValueNames().Return([]string{}, nil)
		k.EXPECT().ReadSubKeyNames().Return([]string{}, nil)
		k.EXPECT().Close().Return(nil)
		return k, nil
	}
	cfg := model.Registry{
		Enabled: true,
		Paths:   []model.RegistryPath{{Hive: "HKLM", Key: "SOFTWARE"}, {Hive: "HKCU", Key: ""}},
	}
	views := registry.SelectViews(cfg, 0x64, 0x32)
	registry.WalkAll(context.Background(), stats.New(t.Name()), cfg, views, open, func(model.Entry, error) bool { return true })

	require.Len(t, calls, 2) // one view × two paths
	assert.Equal(t, openCall{"HKLM", "SOFTWARE", 0x64}, calls[0])
	assert.Equal(t, openCall{"HKCU", "", 0x64}, calls[1])
}

func TestWalkAll_WOW64_opensBothViews(t *testing.T) {
	ctrl := gomock.NewController(t)
	var accesses []uint32
	open := func(hive, key string, access uint32) (registry.RegistryKey, error) {
		accesses = append(accesses, access)
		k := mock.NewMockRegistryKey(ctrl)
		k.EXPECT().ReadValueNames().Return([]string{}, nil)
		k.EXPECT().ReadSubKeyNames().Return([]string{}, nil)
		k.EXPECT().Close().Return(nil)
		return k, nil
	}
	cfg := model.Registry{
		Enabled: true,
		WOW64:   true,
		Paths:   []model.RegistryPath{{Hive: "HKLM", Key: "SOFTWARE"}},
	}
	views := registry.SelectViews(cfg, 0x64, 0x32)
	registry.WalkAll(context.Background(), stats.New(t.Name()), cfg, views, open, func(model.Entry, error) bool { return true })

	require.Equal(t, []uint32{0x64, 0x32}, accesses) // single path scanned in both views
}

func TestWalkAll_OpenError_continuesToNextPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	open := func(hive, key string, access uint32) (registry.RegistryKey, error) {
		if hive == "HKLM" {
			return nil, errors.New("access denied")
		}
		k := mock.NewMockRegistryKey(ctrl)
		k.EXPECT().ReadValueNames().Return([]string{"cert"}, nil)
		k.EXPECT().ReadValueType("cert").Return(uint32(3), nil)
		k.EXPECT().ReadBinaryValue("cert").Return([]byte{0x01}, nil)
		k.EXPECT().ReadSubKeyNames().Return([]string{}, nil)
		k.EXPECT().Close().Return(nil)
		return k, nil
	}
	cfg := model.Registry{
		Enabled: true,
		Paths:   []model.RegistryPath{{Hive: "HKLM", Key: "Bad"}, {Hive: "HKCU", Key: "Good"}},
	}
	views := registry.SelectViews(cfg, 0x64, 0x32)
	var entries []model.Entry
	var errs []error
	registry.WalkAll(context.Background(), stats.New(t.Name()), cfg, views, open, func(e model.Entry, err error) bool {
		if err != nil {
			errs = append(errs, err)
		} else {
			entries = append(entries, e)
		}
		return true
	})

	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "registry: open HKLM\\Bad")
	require.Len(t, entries, 1) // HKCU path still scanned despite HKLM open failure
}

func TestWalkAll_disabled_yieldsNothing(t *testing.T) {
	called := false
	open := func(string, string, uint32) (registry.RegistryKey, error) {
		called = true
		return nil, nil
	}
	cfg := model.Registry{Enabled: false, Paths: []model.RegistryPath{{Hive: "HKLM"}}}
	views := registry.SelectViews(cfg, 0x64, 0x32)
	registry.WalkAll(context.Background(), stats.New(t.Name()), cfg, views, open, func(model.Entry, error) bool { return true })
	assert.False(t, called)
}

func TestBuildLocation_escapesSpecialChars(t *testing.T) {
	loc := registry.BuildLocation("HKLM", "64", "SOFTWARE/My App", "cert #1")
	assert.Equal(t, "registry://HKLM:64/SOFTWARE/My%20App/cert%20%231", loc)
}

func TestBuildLocation_defaultValueVerbatim(t *testing.T) {
	loc := registry.BuildLocation("HKCU", "64", "SOFTWARE", "")
	assert.Equal(t, "registry://HKCU:64/SOFTWARE/(Default)", loc)
}

func TestBuildLocation_emptyKeyPath(t *testing.T) {
	loc := registry.BuildLocation("HKCU", "64", "", "val")
	assert.Equal(t, "registry://HKCU:64/val", loc)
}
