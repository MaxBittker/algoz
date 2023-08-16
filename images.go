package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/bluesky-social/indigo/api/atproto"
	bsky "github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/xrpc"
	. "github.com/whyrusleeping/algoz/models"
	"gorm.io/gorm"
)

type ImageProcessor struct {
	ic *ImageEmbedder
	db *gorm.DB

	xrpcc *xrpc.Client
}

type AddLabelFunc func(context.Context, string, *PostRef) error

func NewImageProcessor(embedderHost string, db *gorm.DB, xrpcc *xrpc.Client) *ImageProcessor {
	ic := &ImageEmbedder{
		Host: embedderHost,
	}

	return &ImageProcessor{
		ic:    ic,
		db:    db,
		xrpcc: xrpcc,
	}
}

func (ip *ImageProcessor) HandlePost(ctx context.Context, u *User, pref *PostRef, rec *bsky.FeedPost) error {
	if rec.Embed != nil && rec.Embed.EmbedImages != nil {
		for _, img := range rec.Embed.EmbedImages.Images {
			hash, embedding, err := ip.fetchAndEmbedImage(ctx, ip.db, u.Did, img)

			strs := make([]string, len(embedding))
			for i, f := range embedding {
				strs[i] = strconv.FormatFloat(f, 'f', -1, 64)
			}

			// join strings with comma and add brackets
			result := fmt.Sprintf("[%s]", strings.Join(strs, ","))

			ip.db.Exec(("INSERT INTO images (ref, hash, embedding) VALUES (?, ?, ?)"), pref.ID, hash, result)

			// log.Error(class)
			if err != nil {
				return fmt.Errorf("classification failed: %w", err)
			}

		}
	}

	return nil
}

func (ip *ImageProcessor) fetchAndEmbedImage(ctx context.Context, db *gorm.DB, did string, img *bsky.EmbedImages_Image) (string, []float64, error) {
	blob, err := atproto.SyncGetBlob(ctx, ip.xrpcc, img.Image.Ref.String(), did)

	if err != nil {
		return "", nil, err
	}

	hash := sha256.Sum256(blob)
	hashStr := hex.EncodeToString(hash[:])

	//check if we already have it

	var image Image
	result := db.Limit(1).First(&image, "hash = ?", hashStr)
	if result.Error == nil {
		return hashStr, []float64(image.Embedding), nil
	}

	embedding, err := ip.ic.Embed(ctx, blob)

	return hashStr, embedding, err
}

func (ip *ImageProcessor) HandleLike(context.Context, *User, *bsky.FeedPost) error {
	return nil
}

func (ip *ImageProcessor) HandleRepost(context.Context, *User, *bsky.FeedPost) error {
	return nil
}
