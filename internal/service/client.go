package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/CZERTAINLY/CBOM-lens/internal/model"
)

const uploadPath = "api/v1/bom"

// contentTypeForVersion labels uploads with the configured CycloneDX spec
// version. Empty (unset) keeps the historical 1.6 label byte-identical.
func contentTypeForVersion(version string) string {
	if version == "" {
		version = "1.6"
	}
	return "application/vnd.cyclonedx+json; version = " + version
}

type UploadCallbackFunc func(error, string, string)

type BOMRepoUploader struct {
	requestURL  string
	contentType string
	client      *http.Client

	uploadCallback UploadCallbackFunc
}

func NewBOMRepoUploader(serverURL model.URL, version string) (*BOMRepoUploader, error) {
	parsedURL := serverURL.Clone().AsURL()
	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")

	parsedURL.Path = fmt.Sprintf("%s/%s", parsedURL.Path, uploadPath)

	c := &BOMRepoUploader{
		requestURL:  parsedURL.String(),
		contentType: contentTypeForVersion(version),
		client:      &http.Client{},
	}

	return c, nil
}

func (c *BOMRepoUploader) WithUploadCallback(fn UploadCallbackFunc) *BOMRepoUploader {
	c.uploadCallback = fn
	return c
}

func (c *BOMRepoUploader) Upload(ctx context.Context, jobName string, raw []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.requestURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", c.contentType)

	resp, err := c.client.Do(req)
	if err != nil {
		if c.uploadCallback != nil {
			c.uploadCallback(err, jobName, "")
		}
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	createRespJson, err := c.decodeUploadResponse(resp)
	if err != nil {
		if c.uploadCallback != nil {
			c.uploadCallback(err, jobName, "")
		}
		return err
	}
	if c.uploadCallback != nil {
		c.uploadCallback(nil, jobName, createRespJson)
	}
	slog.InfoContext(ctx, "BOM uploaded successfully.")

	return nil
}

func (c *BOMRepoUploader) decodeUploadResponse(resp *http.Response) (string, error) {
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return "", fmt.Errorf("failed to parse response content type header: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		if contentType != "application/json" {
			return "", fmt.Errorf("expected `application/json` content type, got: %s", contentType)
		}
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("`io.ReadAll()` failed: %w", err)
		}

		return string(b), nil

	case http.StatusBadRequest:
		fallthrough
	case http.StatusConflict:
		fallthrough
	case http.StatusUnsupportedMediaType:
		if contentType != "application/problem+json" {
			return "", fmt.Errorf("expected `application/problem+json` content type, got: %s", contentType)
		}
		var problemDetail struct {
			Detail string `json:"detail"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&problemDetail); err != nil {
			return "", fmt.Errorf("decoding json response failed: %w", err)
		}
		return "", fmt.Errorf("status code: %d, detail: %s", resp.StatusCode, problemDetail.Detail)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return "", fmt.Errorf("unknown error, status: %d, body: %s", resp.StatusCode, string(respBody))
}
