package service_test

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
	scan "github.com/CZERTAINLY/CBOM-lens/internal/service"
	"github.com/CZERTAINLY/CBOM-lens/internal/stats"
	"github.com/CZERTAINLY/CBOM-lens/internal/walk"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestScanner_Do(t *testing.T) {
	t.Parallel()

	root := fstest.MapFS{
		"is-script": &fstest.MapFile{
			Data:    []byte("#!/bin/sh"),
			Mode:    0644,
			ModTime: time.Now(),
		},
		"dir": &fstest.MapFile{
			Mode:    0755 | fs.ModeDir,
			ModTime: time.Now(),
		},
		"dir/not-a-script": &fstest.MapFile{
			Data:    []byte("not a script"),
			Mode:    0644,
			ModTime: time.Now(),
		},
	}

	isScript := NewMockDetector(t)
	noMatch := NewMockDetector(t)

	isScript.On("Detect", mock.Anything, []byte("#!/bin/sh"), "fstest::/is-script").
		Return([]model.Detection{{Location: "fstest::/is-script"}}, nil).
		Once()
	isScript.On("Detect", mock.Anything, []byte("not a script"), "fstest::/dir/not-a-script").
		Return(nil, model.ErrNoMatch).
		Once()

	noMatch.On("Detect", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, model.ErrNoMatch).
		Times(2)

	detectors := []scan.Detector{noMatch, isScript}
	counter := stats.New(t.Name())
	scanner := scan.New(4, counter, detectors)
	detections := make([]model.Detection, 0, 10)
	for detection, err := range scanner.Do(t.Context(), walk.FS(t.Context(), counter, root, "fstest::")) {
		if errors.Is(err, model.ErrNoMatch) {
			continue
		}
		require.NoError(t, err)
		detections = append(detections, detection...)
	}

	require.Len(t, detections, 1)
	require.Equal(t, "fstest::/is-script", detections[0].Location)
	istats := scanner.Stats()
	require.NotNil(t, istats)
	stats := maps.Collect(counter.Stats())
	t.Logf("stats=%+v", stats)

	for key, value := range counter.Stats() {
		var exp = "0"
		switch {
		case strings.HasSuffix(key, "files_total"):
			exp = "2"
		}
		require.Equal(t, exp, value, key)
	}
}

func TestScanner_Do_Permissions(t *testing.T) {
	tempdir := t.TempDir()
	root, err := os.OpenRoot(tempdir)
	require.NoError(t, err)

	err = root.Mkdir("a", 0o755)
	require.NoError(t, err)
	aTXT, err := root.Create("a/a.txt")
	require.NoError(t, err)
	_, err = aTXT.Write([]byte("hello a.txt\n"))
	require.NoError(t, err)
	err = root.Mkdir("a/b", 0o755)
	require.NoError(t, err)
	err = root.Mkdir("a/X", 0o755)
	require.NoError(t, err)
	xTXT, err := root.Create("a/X/X.txt")
	require.NoError(t, err)
	_, err = xTXT.Write([]byte("X.txt is not accessible\n"))
	require.NoError(t, err)

	// simulate permission denied error on a/X
	err = os.Chmod(filepath.Join(tempdir, "a", "X", "X.txt"), 0x000)
	require.NoError(t, err)
	t.Cleanup(
		func() {
			err = os.Chmod(filepath.Join(tempdir, "a", "X", "X.txt"), 0o755)
			require.NoError(t, err)
		})

	counter := stats.New(t.Name())
	noMatch := NewMockDetector(t)
	noMatch.On("Detect", mock.Anything, mock.Anything, mock.Anything).
		Return(nil, model.ErrNoMatch).
		Times(1)
	scanner := scan.New(1, counter, []scan.Detector{noMatch})
	require.NotNil(t, scanner)

	seq := walk.Roots(t.Context(), counter, root)
	// this is needed to process results
	for detections, err := range scanner.Do(t.Context(), seq) {
		t.Logf("detections: %+v", detections)
		t.Logf("err=%+v", err)
	}

	for key, value := range counter.Stats() {
		var exp = "0"
		switch {
		case strings.HasSuffix(key, "files_total"):
			exp = "2"
		case strings.HasSuffix(key, "files_errors"):
			exp = "1"
		}
		require.Equal(t, exp, value, key)
	}
}

type MockDetector struct {
	mock.Mock
}

func NewMockDetector(t *testing.T) *MockDetector {
	d := new(MockDetector)
	t.Cleanup(func() { d.AssertExpectations(t) })
	return d
}

func (d *MockDetector) Detect(ctx context.Context, b []byte, path string) ([]model.Detection, error) {
	args := d.Called(ctx, b, path)
	var ret []model.Detection
	if x, ok := args.Get(0).([]model.Detection); ok {
		ret = x
	}
	return ret, args.Error(1)
}
