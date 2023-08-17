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
	"github.com/bluesky-social/indigo/util"
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

			ip.db.Exec(("INSERT INTO images (ref, hash, embedding) VALUES (?, ?, ?)"), pref.ID, hash, embedding)
			if err := ip.db.Model(&PostRef{}).Where("id = ?", pref.ID).Update("embedded", true).Error; err != nil {
				return err
			}

			// log.Error(class)
			if err != nil {
				return fmt.Errorf("embedding failed: %w", err)
			}

		}
	}

	return nil
}

func (ip *ImageProcessor) HandleLike(ctx context.Context, u *User, pref *PostRef, rec *bsky.FeedPost, uri string) error {
	if rec.Embed != nil && rec.Embed.EmbedImages != nil {
		for _, img := range rec.Embed.EmbedImages.Images {

			puri, err := util.ParseAtUri(uri)
			if err != nil {
				return fmt.Errorf("ParseAtUri failed: %w", err)
			}
			hash, embedding, err := ip.fetchAndEmbedImage(ctx, ip.db, puri.Did, img)

			if err != nil {
				return fmt.Errorf("fetch & embed failed: %w", err)
			}

			ip.db.Exec(("INSERT INTO images (ref, hash, embedding) VALUES (?, ?, ?)"), pref.ID, hash, embedding)
			if err := ip.db.Model(&PostRef{}).Where("id = ?", pref.ID).Update("embedded", true).Error; err != nil {
				return err
			}

			// log.Error(class)
			if err != nil {
				return fmt.Errorf("embedding failed: %w", err)
			}

		}
	}

	return nil
}

func (ip *ImageProcessor) fetchAndEmbedImage(ctx context.Context, db *gorm.DB, did string, img *bsky.EmbedImages_Image) (string, string, error) {
	blob, err := atproto.SyncGetBlob(ctx, ip.xrpcc, img.Image.Ref.String(), did)

	if err != nil {
		return "", "", err
	}

	hash := sha256.Sum256(blob)
	hashStr := hex.EncodeToString(hash[:])

	//check if we already have it

	type imgRow struct {
		Hash      string
		Embedding string
	}
	var image imgRow
	result := db.Table("images").
		Where("hash = ?", hashStr).
		Limit(1).
		Scan(&image)

	if result.Error == nil && result.RowsAffected > 0 {
		return hashStr, image.Embedding, nil
	}

	embedding, err := ip.ic.Embed(ctx, blob)

	strs := make([]string, len(embedding))
	for i, f := range embedding {
		strs[i] = strconv.FormatFloat(f, 'f', -1, 64)
	}

	// join strings with comma and add brackets
	embeddingString := fmt.Sprintf("[%s]", strings.Join(strs, ","))

	return hashStr, embeddingString, err
}

func (ip *ImageProcessor) HandleRepost(context.Context, *User, *bsky.FeedPost) error {
	return nil
}
