package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
)

type ImageEmbedder struct {
	Host string
}

func (ic *ImageEmbedder) Embed(ctx context.Context, img []byte) ([]float64, error) {
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)

	// Add file to the request
	part, err := writer.CreateFormFile("upload", "image.jpg")
	if err != nil {
		return nil, err
	}
	part.Write(img)

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(ic.Host + "/embed_image/")
	if err != nil {
		return nil, err
	}

	// Create the request
	req, err := http.NewRequest("POST", u.String(), &buffer)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request

	type Response struct {
		FileSize int64       `json:"file_size"`
		Values   [][]float64 `json:"values"`
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// check the response
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code %d", res.StatusCode)
	}

	var out Response

	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}

	return out.Values[0], nil
}
