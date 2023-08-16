package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	api "github.com/bluesky-social/indigo/api"
	"github.com/bluesky-social/indigo/api/atproto"
	bsky "github.com/bluesky-social/indigo/api/bsky"
	cliutil "github.com/bluesky-social/indigo/cmd/gosky/util"
	"github.com/bluesky-social/indigo/did"
	"github.com/bluesky-social/indigo/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	es256k "github.com/ericvolp12/jwt-go-secp256k1"
	"github.com/golang-jwt/jwt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/whyrusleeping/algoz/models"
	. "github.com/whyrusleeping/algoz/models"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/crypto/acme/autocert"

	cli "github.com/urfave/cli/v2"

	gorm "gorm.io/gorm"
	"gorm.io/gorm/clause"
)

//type User = models.User
//type PostRef = models.PostRef
//type FeedLike = models.FeedLike
//type FeedRepost = models.FeedRepost
//type Feed = models.Feed

var EpochOne time.Time = time.Unix(1, 1)

var log = logging.Logger("algoz")

type FeedBuilder interface {
	Name() string
	Description() string
	GetFeed(context.Context, *User, int, *string) (*bsky.FeedGetFeedSkeleton_Output, error)
	Processor
}

type Labeler interface {
	Processor
}

type Processor interface {
	HandlePost(context.Context, *User, *PostRef, *bsky.FeedPost) error
	HandleLike(context.Context, *User, *bsky.FeedPost) error
	HandleRepost(context.Context, *User, *bsky.FeedPost) error
}

type LastSeq struct {
	ID  uint `gorm:"primarykey"`
	Seq int64
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{}
	app.Commands = []*cli.Command{
		runCmd,
	}

	app.RunAndExitOnError()
}

type Server struct {
	db      *gorm.DB
	bgshost string
	xrpcc   *xrpc.Client
	bgsxrpc *xrpc.Client
	didr    did.Resolver

	processors []Processor
	fbm        map[string]FeedBuilder

	feeds  []feedSpec
	didDoc *did.Document

	userLk    sync.Mutex
	userCache *lru.Cache
	keyCache  *lru.Cache
}

type feedSpec struct {
	Name        string
	Uri         string
	Description string
}

var runCmd = &cli.Command{
	Name: "run",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "database-url",
			Value:   "sqlite://data/algoz.db",
			EnvVars: []string{"DATABASE_URL"},
		},
		&cli.StringFlag{
			Name:    "atp-bgs-host",
			Value:   "wss://bsky.social",
			EnvVars: []string{"ATP_BGS_HOST"},
		},
		&cli.BoolFlag{
			Name:    "classifier-mode",
			EnvVars: []string{"CLASSIFIER_MODE"},
		},
		&cli.StringFlag{
			Name:  "plc-host",
			Value: "https://plc.directory",
		},
		&cli.StringFlag{
			Name:  "pds-host",
			Value: "https://bsky.social",
		},
		&cli.StringFlag{
			Name: "did-doc",
		},
		&cli.StringFlag{
			Name: "auto-tls-domain",
		},
		&cli.BoolFlag{
			Name: "no-index",
		},
		&cli.StringFlag{
			Name: "img-class-host",
		},
	},
	Action: func(cctx *cli.Context) error {

		log.Info("Connecting to database")
		db, err := cliutil.SetupDatabase(cctx.String("database-url"))
		if err != nil {
			return err
		}
		// CREATE INDEX idx_post_uid_is_reply_createdON post_refs (uid, is_reply, created_at DESC);
		// CREATE INDEX idx_post_uid_is_reply_created_atON post_refs (uid, is_reply, created_at DESC);
		// CREATE INDEX idx_post_uid_rkeyON post_refs (uid, rkey);
		// CREATE INDEX idx_follows_uid_rkeyON follows (uid, rkey);
		// log.Info("Migrating database")
		// db.AutoMigrate(&models.User{})
		// db.Exec("ALTER TABLE users ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE users SET temp_id = id;")
		// db.Exec("ALTER TABLE users DROP COLUMN id;")
		// db.Exec("ALTER TABLE users RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE users ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.Follow{})

		// db.Exec("ALTER TABLE follows ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE follows SET temp_id = id;")
		// db.Exec("ALTER TABLE follows DROP COLUMN id;")
		// db.Exec("ALTER TABLE follows RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE follows ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&LastSeq{})

		// db.Exec("ALTER TABLE last_seqs ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE last_seqs SET temp_id = id;")
		// db.Exec("ALTER TABLE last_seqs DROP COLUMN id;")
		// db.Exec("ALTER TABLE last_seqs RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE last_seqs ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.PostRef{})

		// db.Exec("ALTER TABLE post_refs ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE post_refs SET temp_id = id;")
		// db.Exec("ALTER TABLE post_refs DROP COLUMN id;")
		// db.Exec("ALTER TABLE post_refs RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE post_refs ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.FeedIncl{})

		// db.Exec("ALTER TABLE feed_incls ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE feed_incls SET temp_id = id;")
		// db.Exec("ALTER TABLE feed_incls DROP COLUMN id;")
		// db.Exec("ALTER TABLE feed_incls RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE feed_incls ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.Feed{})

		// db.Exec("ALTER TABLE feeds ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE feeds SET temp_id = id;")
		// db.Exec("ALTER TABLE feeds DROP COLUMN id;")
		// db.Exec("ALTER TABLE feeds RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE feeds ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.FeedLike{})

		// db.Exec("ALTER TABLE feed_likes ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE  feed_likes SET temp_id = id;")
		// db.Exec("ALTER TABLE feed_likes DROP COLUMN id;")
		// db.Exec("ALTER TABLE feed_likes RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE feed_likes ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.FeedRepost{})

		// db.Exec("ALTER TABLE feed_reposts ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE feed_reposts SET temp_id = id;")
		// db.Exec("ALTER TABLE feed_reposts DROP COLUMN id;")
		// db.Exec("ALTER TABLE feed_reposts RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE feed_reposts ADD PRIMARY KEY (id);")
		// db.AutoMigrate(&models.Block{})

		// db.Exec("ALTER TABLE blocks ADD COLUMN temp_id SERIAL;")
		// db.Exec("UPDATE  blocks  SET temp_id = id;")
		// db.Exec("ALTER TABLE blocks DROP COLUMN id;")
		// db.Exec("ALTER TABLE blocks RENAME COLUMN temp_id TO id;")
		// db.Exec("ALTER TABLE blocks ADD PRIMARY KEY (id);")
		//exit the process:

		// db.Exec("CREATE TABLE images (id SERIAL PRIMARY KEY, Ref bigint, hash CHAR(64), embedding vector(512));");

		// os.Exit(0)

		log.Infof("Configuring HTTP server")
		e := echo.New()
		e.Use(middleware.Logger())
		e.HTTPErrorHandler = func(err error, c echo.Context) {
			log.Error(err)
		}

		xc := &xrpc.Client{
			Host:    cctx.String("pds-host"),
			Headers: map[string]string{},
		}
		if rbt := os.Getenv("RATELIMIT_BYPASS_TOKEN"); rbt != "" {
			xc.Headers["X-Ratelimit-Bypass"] = rbt
		}

		plc := &api.PLCServer{
			Host: cctx.String("plc-host"),
		}

		didr := did.NewMultiResolver()
		didr.AddHandler("plc", plc)
		didr.AddHandler("web", &did.WebResolver{})

		bgsws := cctx.String("atp-bgs-host")
		if !strings.HasPrefix(bgsws, "ws") {
			return fmt.Errorf("specified bgs host must include 'ws://' or 'wss://'")
		}

		bgshttp := strings.Replace(bgsws, "ws", "http", 1)
		bgsxrpc := &xrpc.Client{
			Host:    bgshttp,
			Headers: map[string]string{},
		}
		if rbt := os.Getenv("RATELIMIT_BYPASS_TOKEN"); rbt != "" {
			bgsxrpc.Headers["X-Ratelimit-Bypass"] = rbt
		}

		ucache, _ := lru.New(100000)
		kcache, _ := lru.New(100000)
		s := &Server{
			db:        db,
			bgshost:   cctx.String("atp-bgs-host"),
			xrpcc:     xc,
			bgsxrpc:   bgsxrpc,
			didr:      didr,
			userCache: ucache,
			keyCache:  kcache,
			fbm:       make(map[string]FeedBuilder),
		}

		if d := cctx.String("did-doc"); d != "" {
			doc, err := loadDidDocument(d)
			if err != nil {
				return err
			}

			s.didDoc = doc
		}

		mydid := "did:plc:wmhp7mubpgafjggwvaxeozmu"
		middlebit := mydid + "/app.bsky.feed.generator/"

		// Create some initial feed definitions
		s.feeds = []feedSpec{}

		followpicsuri := "at://" + middlebit + "followpics"
		s.AddFeedBuilder(followpicsuri, &FollowPics{
			s: s,
		})

		cozyuri := "at://" + middlebit + "cozy"
		s.AddFeedBuilder(cozyuri, &GoodFollows{
			s: s,
		})

		enjoyuri := "at://" + middlebit + "enjoy"
		s.AddFeedBuilder(enjoyuri, &EnjoyFeed{
			s: s,
		})

		s.AddProcessor(NewImageProcessor("http://0.0.0.0:8181/", s.db, s.xrpcc))

		for _, f := range s.feeds {
			if err := s.db.Create(&models.Feed{
				Name:        f.Name,
				Description: f.Description,
			}).Error; err != nil {
				fmt.Println(err)
			}
		}

		e.Use(middleware.CORS())
		e.GET("/xrpc/app.bsky.feed.getFeedSkeleton", s.handleGetFeedSkeleton)
		e.GET("/xrpc/app.bsky.feed.describeFeedGenerator", s.handleDescribeFeedGenerator)
		e.GET("/.well-known/did.json", s.handleServeDidDoc)

		atd := cctx.String("auto-tls-domain")
		if atd != "" {
			cachedir, err := os.UserCacheDir()
			if err != nil {
				return err
			}

			e.AutoTLSManager.HostPolicy = autocert.HostWhitelist(atd)
			// Cache certificates to avoid issues with rate limits (https://letsencrypt.org/docs/rate-limits)
			e.AutoTLSManager.Cache = autocert.DirCache(filepath.Join(cachedir, "certs"))
		}
		if !cctx.Bool("classifier-mode") {
			go func() {

				if atd != "" {
					panic(e.StartAutoTLS(":3339"))
				} else {
					panic(e.Start(":3339"))
				}
			}()
		}

		if cctx.Bool("no-index") {
			select {}
		}
		// go func() {
		// 	s.pollAllUsersFollows(context.Background())
		// }()
		ctx := context.TODO()
		if err := s.Run(ctx); err != nil {
			return fmt.Errorf("failed to run: %w", err)
		}

		return nil
	},
}

func (s *Server) pollAllUsersFollows(ctx context.Context) error {
	c := time.Tick(3000 * time.Millisecond)
	for _ = range c {
		var users []User
		if err := s.db.Where("scraped_follows = false").Where("handle is not null").Order("random()").Limit(10).Find(&users).Error; err != nil {
			log.Error(err)
			continue
		}

		// var wg sync.WaitGroup

		// Consumers.
		for i := 0; i < 5; i++ {
			// wg.Add(1)
			u := users[i]
			go func(u *User) {
				// defer wg.Done()
				if !u.HasFollowsScraped() {
					// log.Error(u)
					if err := s.scrapeFollowsForUser(ctx, u); err != nil {
						log.Error("Failed to scrape follows for user %s: %v", u.ID, err)
					}
				}
			}(&u)
		}

		// wg.Wait() // Wait for all goroutines to finish.
	}
	return nil
}

func loadDidDocument(fn string) (*did.Document, error) {
	fi, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer fi.Close()

	var doc did.Document
	if err := json.NewDecoder(fi).Decode(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

func (s *Server) AddProcessor(p Processor) {
	s.processors = append(s.processors, p)
}

func (s *Server) AddFeedBuilder(uri string, fb FeedBuilder) {
	s.AddProcessor(fb)
	s.fbm[uri] = fb

	s.feeds = append(s.feeds, feedSpec{
		Name:        fb.Name(),
		Description: fb.Description(),
		Uri:         uri,
	})
}

type cachedKey struct {
	EOL time.Time
	Key any
}

func (s *Server) getKeyForDid(did string) (any, error) {
	doc, err := s.didr.GetDocument(context.TODO(), did)
	if err != nil {
		return nil, err
	}

	pubk, err := doc.GetPublicKey("#atproto")
	if err != nil {
		return nil, err
	}

	switch pubk.Type {
	case "EcdsaSecp256k1VerificationKey2019":
		pub, err := secp256k1.ParsePubKey(pubk.Raw.([]byte))
		if err != nil {
			return nil, fmt.Errorf("pubkey was invalid: %w", err)
		}

		ecp := pub.ToECDSA()

		return ecp, nil
	default:
		return nil, fmt.Errorf("unrecognized key type: %q", pubk.Type)

	}

}

func (s *Server) fetchKey(tok *jwt.Token) (any, error) {
	issuer, ok := tok.Claims.(jwt.MapClaims)["iss"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'iss' field from auth header")
	}

	val, ok := s.keyCache.Get(issuer)
	if ok {
		ck := val.(*cachedKey)
		if time.Now().Before(ck.EOL) {
			return ck.Key, nil
		}
	}

	k, err := s.getKeyForDid(issuer)
	if err != nil {
		return nil, err
	}

	s.keyCache.Add(issuer, &cachedKey{
		EOL: time.Now().Add(time.Minute * 10),
		Key: k,
	})

	return k, nil
}

type FeedItem struct {
	Post string `json:"post"`
}

func (s *Server) handleGetFeedSkeleton(e echo.Context) error {
	ctx, span := otel.Tracer("algoz").Start(e.Request().Context(), "handleGetFeedSkeleton")
	defer span.End()

	feed := e.QueryParam("feed")

	span.SetAttributes(attribute.String("feed", feed))

	var authedUser *User

	// u, err := s.getOrCreateUser(ctx, "did:plc:wmhp7mubpgafjggwvaxeozmu")
	// if err != nil {
	// 	return fmt.Errorf("failed to create user: %w", err)
	// }

	// authedUser = u
	// span.SetAttributes(attribute.String("did", u.Did))

	if auth := e.Request().Header.Get("Authorization"); auth != "" {
		parts := strings.Split(auth, " ")
		if parts[0] != "Bearer" || len(parts) != 2 {
			return fmt.Errorf("invalid auth header")
		}

		p := new(jwt.Parser)
		p.ValidMethods = []string{es256k.SigningMethodES256K.Alg()}
		tok, err := p.Parse(parts[1], s.fetchKey)
		if err != nil {
			return err
		}
		did := tok.Claims.(jwt.MapClaims)["iss"].(string)
		//did := "did:plc:vpkhqolt662uhesyj6nxm7ys"

		u, err := s.getOrCreateUser(ctx, did)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		authedUser = u
		span.SetAttributes(attribute.String("did", u.Did))
	}

	var limit int = 100
	if lims := e.QueryParam("limit"); lims != "" {
		v, err := strconv.Atoi(lims)
		if err != nil {
			return err
		}
		limit = v
	}

	// TODO: technically should be checking that the full URI matches
	puri, err := util.ParseAtUri(feed)
	if err != nil {
		return err
	}

	var cursor *string
	if c := e.QueryParam("cursor"); c != "" {
		cursor = &c
	}

	span.SetAttributes(attribute.Bool("cursor", cursor != nil))

	fb, ok := s.fbm[feed]
	if ok {
		out, err := fb.GetFeed(ctx, authedUser, limit, cursor)
		if err != nil {
			return &echo.HTTPError{
				Code:    500,
				Message: fmt.Sprintf("getFeed failed: %s", err),
			}
		}

		return e.JSON(200, out)
	}

	switch puri.Rkey {
	case "cats", "dogs", "nsfw", "seacreatures", "flowers":
		// all of these feeds are fed by the same 'feed_incls' table
		feed, outcurs, err := s.getFeed(ctx, puri.Rkey, limit, cursor)
		if err != nil {
			return err
		}

		return e.JSON(200, &bsky.FeedGetFeedSkeleton_Output{
			Feed:   feed,
			Cursor: outcurs,
		})
	case "upandup":
		feed, outcurs, err := s.getFeedAddOrder(ctx, puri.Rkey, limit, cursor)
		if err != nil {
			return err
		}

		return e.JSON(200, &bsky.FeedGetFeedSkeleton_Output{
			Feed:   feed,
			Cursor: outcurs,
		})
	case "mostpop":
		// mostpop is fed by a sql query over all the posts
		feed, curs, err := s.getMostPop(ctx, limit, cursor)
		if err != nil {
			return err
		}

		return e.JSON(200, &bsky.FeedGetFeedSkeleton_Output{
			Feed:   feed,
			Cursor: curs,
		})
	case "river":
		if authedUser == nil {
			return &echo.HTTPError{
				Code:    403,
				Message: "auth required for feed",
			}
		}
		feed, outcurs, err := s.getSimilarToLikes(ctx, authedUser, limit, cursor)
		if err != nil {
			return err
		}

		return e.JSON(200, &bsky.FeedGetFeedSkeleton_Output{
			Feed:   feed,
			Cursor: outcurs,
		})
	case "bestoffollows":
		if authedUser == nil {
			return &echo.HTTPError{
				Code:    403,
				Message: "auth required for feed",
			}
		}
		feed, outcurs, err := s.getMostRecentFromFollows(ctx, authedUser, limit, cursor)
		if err != nil {
			return err
		}

		return e.JSON(200, &bsky.FeedGetFeedSkeleton_Output{
			Feed:   feed,
			Cursor: outcurs,
		})
	default:
		return &echo.HTTPError{
			Code:    400,
			Message: "no such feed",
		}
	}
}

func (s *Server) getMostPop(ctx context.Context, limit int, cursor *string) ([]*bsky.FeedDefs_SkeletonFeedPost, *string, error) {
	// Get current time
	now := time.Now().UTC().Truncate(time.Minute * 10)

	if cursor != nil {
		tc, err := parseTimeCursor(*cursor)
		if err != nil {
			return nil, nil, err
		}

		now = tc.UTC().Truncate(time.Minute * 10)
	}

	// Get the time 6 hours ago
	sixHoursAgo := now.Add(-6 * time.Hour)

	// Raw SQL query
	query := `
		SELECT *
		FROM post_refs
		LEFT JOIN users on post_refs.uid = users.id
		WHERE (users.blocked IS NULL OR users.blocked = false) AND post_refs.created_at BETWEEN $1 AND $2
		ORDER BY likes DESC
		LIMIT 1
	`

	// Initialize an empty slice to store the posts
	var posts []PostRef

	// Iterate over each 10-minute window in the past 6 hours
	for t := now; t.After(sixHoursAgo); t = t.Add(-10 * time.Minute) {
		// Define the start and end of the window
		windowEnd := t
		windowStart := t.Add(-10 * time.Minute)

		// Convert to PostgreSQL-compatible datetime strings
		windowStartStr := windowStart.Format("2006-01-02 15:04:05")
		windowEndStr := windowEnd.Format("2006-01-02 15:04:05")

		// Execute query and scan the results into a PostRef
		var post PostRef
		if err := s.db.Raw(query, windowStartStr, windowEndStr).Scan(&post).Error; err != nil {
			// If an error occurred, return the error
			return nil, nil, err
		}

		if post.ID > 0 {
			// Add the post to the slice of posts
			posts = append(posts, post)
		}

		if len(posts) >= limit {
			break
		}
	}

	skelposts, err := s.postsToFeed(ctx, posts)
	if err != nil {
		return nil, nil, err
	}

	outcurs := posts[len(posts)-1].CreatedAt.UTC().Format(time.RFC3339)

	return skelposts, &outcurs, nil
}

func (s *Server) scrapeFollowsForUser(ctx context.Context, u *User) error {
	log.Error("scraping " + u.Handle)
	var cursor string
	for {
		resp, err := atproto.RepoListRecords(ctx, s.xrpcc, "app.bsky.graph.follow", cursor, 100, u.Did, false, "", "")
		if err != nil {
			return err
		}

		for _, rec := range resp.Records {
			fol := rec.Value.Val.(*bsky.GraphFollow)

			puri, err := util.ParseAtUri(rec.Uri)
			if err != nil {
				return err
			}

			// TODO: technically need to pass collection/rkey here, but this works
			if err := s.handleFollow(ctx, u, fol, puri.Rkey); err != nil {
				return err
			}
		}

		if len(resp.Records) == 0 {
			break
		}

		if resp.Cursor == nil {
			log.Warnf("no cursor set in response from list records")
			break
		}
		cursor = *resp.Cursor
	}

	if err := s.db.Debug().Table("users").Where("id = ?", u.ID).Update("scraped_follows", true).Error; err != nil {
		return err
	}
	u.SetFollowsScraped(true)

	return nil
}

func (s *Server) latestPostForUser(ctx context.Context, uid uint) (*PostRef, error) {
	var u User
	if err := s.db.First(&u, "id = ?", uid).Error; err != nil {
		return nil, err
	}

	lp := u.LatestPost

	if lp == 0 {
		var p PostRef
		if err := s.db.Order("created_at DESC").Limit(1).Find(&p, "uid = ? AND NOT is_reply", uid).Error; err != nil {
			return nil, err
		}

		if p.ID == 0 {
			return nil, nil
		}

		if err := s.setUserLastPost(&u, &p); err != nil {
			return nil, err
		}

		return &p, nil
	} else {
		var p PostRef
		if err := s.db.Find(&p, "id = ?", lp).Error; err != nil {
			return nil, err
		}

		if p.ID == 0 {
			return nil, nil
		}

		return &p, nil
	}
}

func backfillLatestPost(ctx context.Context, s *Server, u *User, limit int, start int) {
	var fusers []User
	s.db.Table("follows as f1").
		Joins("LEFT JOIN users on f1.following = users.id").
		Where("f1.uid = ?", u.ID).
		// Order("random()").
		// Limit(limit).
		Offset(start).
		Scan(&fusers)

	for _, f := range fusers {
		// log.Error(f)
		if !f.HasFollowsScraped() {
			s.scrapeFollowsForUser(ctx, &f)
		}

		if f.LatestPost == 0 {
			s.latestPostForUser(ctx, f.ID)
		}
	}
}

func (s *Server) getSimilarToLikes(ctx context.Context, u *User, limit int, cursor *string) ([]*bsky.FeedDefs_SkeletonFeedPost, *string, error) {
	start := 0
	if cursor != nil {
		num, err := strconv.Atoi(*cursor)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cursor: %w", err)
		}

		start = num
	}

	var out []PostRef

	err := s.db.Table("images").Select("post_refs.*").
		Joins("JOIN post_refs ON post_refs.id = images.ref").
		Where("images.id IS NOT NULL AND NOT post_refs.is_reply").
		Order("random()").
		Limit(limit).
		Offset(start).
		Scan(&out).Error

	if err != nil {
		return nil, nil, err
	}

	fp, err := s.postsToFeed(ctx, out)
	if err != nil {
		return nil, nil, err
	}

	curs := fmt.Sprint(start + limit)

	return fp, &curs, nil
}

func (s *Server) getMostRecentFromFollows(ctx context.Context, u *User, limit int, cursor *string) ([]*bsky.FeedDefs_SkeletonFeedPost, *string, error) {
	if !u.HasFollowsScraped() {
		if err := s.scrapeFollowsForUser(ctx, u); err != nil {
			return nil, nil, err
		}
	}

	start := 0
	if cursor != nil {
		num, err := strconv.Atoi(*cursor)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cursor: %w", err)
		}

		start = num
	}
	var out []PostRef

	err := s.db.Table("follows as f1").
		Joins("INNER JOIN follows as f2 on f1.following = f2.uid").
		Joins("INNER JOIN users on f2.uid = users.id").
		Joins(`INNER JOIN post_refs on post_refs.id =
		 (SELECT id FROM ( 
			SELECT id FROM "post_refs"
			WHERE uid = users.id AND NOT is_reply
			ORDER BY created_at DESC
			LIMIT 5
		 )post_refs_ordered
		  ORDER BY random()
		  LIMIT 1)
		 `).
		Where("f1.uid = ? AND f2.following = ?", u.ID, u.ID).
		Order("random()").
		Limit(limit).
		Offset(start).
		Scan(&out).Error

	if err != nil {
		return nil, nil, err
	}

	// var out []PostRef
	// if err := s.db.Table("follows as f1").
	// 	Joins("INNER JOIN follows as f2 on f1.following = f2.uid").
	// 	Joins("INNER JOIN users on f2.uid = users.id").
	// 	Joins("INNER JOIN post_refs on users.latest_post = post_refs.id").
	// 	Where("f1.uid = ? AND f2.following = ?", u.ID, u.ID).
	// 	Where("users.latest_post > 0").
	// 	Order("random()").
	// 	Limit(limit).
	// 	Offset(start).
	// 	Scan(&out).Error; err != nil {
	// 	return nil, nil, err
	// }

	fp, err := s.postsToFeed(ctx, out)
	if err != nil {
		return nil, nil, err
	}

	curs := fmt.Sprint(start + limit)

	ctxAsync, _ := context.WithCancel(context.Background())
	go backfillLatestPost(ctxAsync, s, u, limit, start)

	return fp, &curs, nil
}

func (s *Server) postsToFeed(ctx context.Context, posts []PostRef) ([]*bsky.FeedDefs_SkeletonFeedPost, error) {
	out := []*bsky.FeedDefs_SkeletonFeedPost{}
	for _, p := range posts {
		uri, err := s.uriForPost(ctx, &p)
		if err != nil {
			return nil, err
		}

		out = append(out, &bsky.FeedDefs_SkeletonFeedPost{Post: uri})
	}

	return out, nil
}

func parseTimeCursor(c string) (time.Time, error) {
	return time.Parse(time.RFC3339, c)
}

// same as normal getFeed, except it sorts by when the post was added to the feed, not by post creation date
func (s *Server) getFeedAddOrder(ctx context.Context, feed string, limit int, cursor *string) ([]*bsky.FeedDefs_SkeletonFeedPost, *string, error) {
	log.Infof("serving %s", feed)
	f, err := s.getFeedRef(ctx, feed)
	if err != nil {
		return nil, nil, err
	}

	var posts []PostRef
	q := s.db.Table("feed_incls").Where("feed_incls.feed = ?", f.ID).Joins("INNER JOIN post_refs on post_refs.id = feed_incls.post").Select("post_refs.*").Order("feed_incls.id desc").Limit(limit)
	if cursor != nil {
		curs, err := strconv.Atoi(*cursor)
		if err != nil {
			return nil, nil, err
		}

		q = q.Where("feed_incls.id < ?", curs)
	}
	if err := q.Find(&posts).Error; err != nil {
		return nil, nil, err
	}

	skelposts, err := s.postsToFeed(ctx, posts)
	if err != nil {
		return nil, nil, err
	}

	if len(skelposts) == 0 {
		return []*bsky.FeedDefs_SkeletonFeedPost{}, nil, nil
	}

	var outcursv int
	if err := s.db.Table("feed_incls").Where("feed = ? AND post = ?", f.ID, posts[len(posts)-1].ID).Select("id").Scan(&outcursv).Error; err != nil {
		return nil, nil, err
	}
	outcurs := fmt.Sprint(outcursv)

	return skelposts, &outcurs, nil
}

func (s *Server) getFeed(ctx context.Context, feed string, limit int, cursor *string) ([]*bsky.FeedDefs_SkeletonFeedPost, *string, error) {
	ctx, span := otel.Tracer("algoz").Start(ctx, "getFeed")
	defer span.End()

	f, err := s.getFeedRef(ctx, feed)
	if err != nil {
		return nil, nil, err
	}

	var posts []PostRef
	q := s.db.Table("feed_incls").Where("feed_incls.feed = ?", f.ID).Joins("INNER JOIN post_refs on post_refs.id = feed_incls.post").Select("post_refs.*").Order("post_refs.created_at desc").Limit(limit)
	if cursor != nil {
		t, err := time.Parse(time.RFC3339, *cursor)
		if err != nil {
			return nil, nil, err
		}

		q = q.Where("post_refs.created_at < ?", t)
	}
	if err := q.Find(&posts).Error; err != nil {
		return nil, nil, err
	}

	if len(posts) == 0 {
		return []*bsky.FeedDefs_SkeletonFeedPost{}, nil, nil
	}

	skelposts, err := s.postsToFeed(ctx, posts)
	if err != nil {
		return nil, nil, err
	}

	outcurs := posts[len(posts)-1].CreatedAt.Format(time.RFC3339)

	return skelposts, &outcurs, nil
}

func (s *Server) uriForPost(ctx context.Context, pr *PostRef) (string, error) {
	var u User
	if err := s.db.First(&u, "id = ?", pr.Uid).Error; err != nil {
		return "", err
	}

	return "at://" + u.Did + "/app.bsky.feed.post/" + pr.Rkey, nil
}

func (s *Server) handleDescribeFeedGenerator(e echo.Context) error {
	var out bsky.FeedDescribeFeedGenerator_Output
	out.Did = s.didDoc.ID.String()
	for _, s := range s.feeds {
		out.Feeds = append(out.Feeds, &bsky.FeedDescribeFeedGenerator_Feed{s.Uri})
	}

	return e.JSON(200, out)
}

type DidResponse struct {
	Context []string      `json:"@context"`
	ID      string        `json:"id"`
	Service []did.Service `json:"service"`
}

func (s *Server) handleServeDidDoc(e echo.Context) error {

	didResponse := DidResponse{
		Context: s.didDoc.Context,
		ID:      s.didDoc.ID.String(),
		Service: s.didDoc.Service,
	}

	return e.JSON(200, didResponse)
}

func (s *Server) deletePost(ctx context.Context, u *User, path string) error {
	log.Debugf("deleting post: %s", path)

	// TODO:
	return nil
}

func (s *Server) deleteLike(ctx context.Context, u *User, path string) error {
	parts := strings.Split(path, "/")

	rkey := parts[len(parts)-1]

	var lk FeedLike
	if err := s.db.Find(&lk, "uid = ? AND rkey = ?", u.ID, rkey).Error; err != nil {
		return err
	}

	if lk.ID == 0 {
		log.Warnf("handling delete with no record reference: %s %s", u.Did, path)
		return nil
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&PostRef{}).Where("id = ?", lk.Ref).Update("likes", gorm.Expr("likes - 1")).Error; err != nil {
			return err
		}

		return tx.Delete(&lk).Error
	})
}

func (s *Server) deleteRepost(ctx context.Context, u *User, path string) error {
	parts := strings.Split(path, "/")

	rkey := parts[len(parts)-1]

	var rp FeedRepost
	if err := s.db.First(&rp, "uid = ? AND rkey = ?", u.ID, rkey).Error; err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&PostRef{}).Where("id = ?", rp.Ref).Update("reposts", gorm.Expr("reposts - 1")).Error; err != nil {
			return err
		}

		return tx.Delete(&rp).Error
	})
}

func (s *Server) deleteFollow(ctx context.Context, u *User, path string) error {
	parts := strings.Split(path, "/")

	rkey := parts[len(parts)-1]

	if err := s.db.Delete(&Follow{}, "uid = ? AND rkey = ?", u.ID, rkey).Error; err != nil {
		return err
	}

	return nil
}

func (s *Server) indexPost(ctx context.Context, u *User, rec *bsky.FeedPost, path string, pcid cid.Cid) error {
	log.Debugf("indexing post: %s", path)

	t, err := time.Parse(util.ISO8601, rec.CreatedAt)
	if err != nil {
		log.Infof("post had invalid creation time: %s", err)
	}

	parts := strings.Split(path, "/")
	rkey := parts[len(parts)-1]

	pref := &PostRef{
		CreatedAt: t,
		Cid:       pcid.String(),
		Rkey:      rkey,
		Uid:       u.ID,
		NotFound:  false,
	}

	if rec.Reply != nil {
		repto, err := s.getPostByUri(ctx, rec.Reply.Parent.Uri)
		if err != nil {
			return err
		}
		pref.ReplyTo = repto.ID
		pref.IsReply = true

		reproot, err := s.getPostByUri(ctx, rec.Reply.Root.Uri)
		if err != nil {
			return err
		}

		pref.ThreadRoot = reproot.ID
	}

	if rec.Embed != nil {
		if rec.Embed.EmbedImages != nil && len(rec.Embed.EmbedImages.Images) > 0 {
			pref.HasImage = true
		}

		var rpref string
		if rec.Embed.EmbedRecord != nil {
			rpref = rec.Embed.EmbedRecord.Record.Uri
		}
		if rec.Embed.EmbedRecordWithMedia != nil {
			rpref = rec.Embed.EmbedRecordWithMedia.Record.Record.Uri
		}
		if rpref != "" && strings.Contains(rpref, "app.bsky.feed.post") {
			rp, err := s.getPostByUri(ctx, rpref)
			if err != nil {
				return err
			}

			pref.Reposting = rp.ID
		}
	}

	// Update columns to default value on `id` conflict
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uid"}, {Name: "rkey"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"cid": "not_found"}),
	}).Create(pref).Error; err != nil {
		return err
	}

	if rec.Reply != nil {
		if err := s.incrementReplyTo(ctx, rec.Reply.Parent.Uri); err != nil {
			return err
		}

		if err := s.incrementReplyRoot(ctx, rec.Reply.Root.Uri); err != nil {
			return err
		}
	} else {
		// track latest post from each user
		if err := s.setUserLastPost(u, pref); err != nil {
			return err
		}
	}

	for _, fb := range s.processors {
		if err := fb.HandlePost(ctx, u, pref, rec); err != nil {
			return err
		}
	}

	/*
		if err := s.addPostToFeed(ctx, "nsfw", pref); err != nil {
			return err
		}
	*/

	return nil
}

func (s *Server) setUserLastPost(u *User, p *PostRef) error {
	// return u.DoLocked(func() error {
	if err := s.db.Table("users").Where("id = ?", u.ID).Update("latest_post", p.ID).Error; err != nil {
		return err
	}
	u.LatestPost = p.ID
	return nil
	// })
}

func (s *Server) incrementReplyTo(ctx context.Context, uri string) error {
	pref, err := s.getPostByUri(ctx, uri)
	if err != nil {
		return err
	}

	if err := s.db.Model(&PostRef{}).Where("id = ?", pref.ID).Update("replies", gorm.Expr("replies + 1")).Error; err != nil {
		return err
	}

	return err
}

func (s *Server) getPostByUri(ctx context.Context, uri string) (*PostRef, error) {
	puri, err := util.ParseAtUri(uri)
	if err != nil {
		return nil, err
	}

	u, err := s.getOrCreateUser(ctx, puri.Did)
	if err != nil {
		return nil, err
	}

	var ref PostRef
	if err := s.db.Find(&ref, "uid = ? AND rkey = ?", u.ID, puri.Rkey).Error; err != nil {
		return nil, err
	}

	if ref.ID == 0 {
		ref.Rkey = puri.Rkey
		ref.Uid = u.ID
		ref.NotFound = true
		ref.CreatedAt = EpochOne

		rec, rcid, err := s.getRecord(ctx, uri)
		if err != nil {
			log.Error("failed to fetch missing record: %s", err)
		} else {
			crt, err := time.Parse(util.ISO8601, rec.CreatedAt)
			if err != nil {
				return nil, err
			}

			ref.CreatedAt = crt
			ref.Cid = rcid.String()
		}

		if err := s.db.Create(&ref).Error; err != nil {
			return nil, err
		}
	}

	return &ref, nil
}

func (s *Server) getRecord(ctx context.Context, uri string) (*bsky.FeedPost, cid.Cid, error) {
	puri, err := util.ParseAtUri(uri)
	if err != nil {
		return nil, cid.Undef, err
	}

	out, err := atproto.RepoGetRecord(ctx, s.xrpcc, "", puri.Collection, puri.Did, puri.Rkey)
	if err != nil {
		return nil, cid.Undef, err
	}

	var c cid.Cid
	if out.Cid != nil {
		cc, err := cid.Decode(*out.Cid)
		if err != nil {
			return nil, cid.Undef, err
		}
		c = cc
	}

	fp, ok := out.Value.Val.(*bsky.FeedPost)
	if !ok {
		return nil, cid.Undef, fmt.Errorf("record was not a feed post")
	}

	return fp, c, nil
}

func (s *Server) incrementReplyRoot(ctx context.Context, uri string) error {
	pref, err := s.getPostByUri(ctx, uri)
	if err != nil {
		return err
	}

	if err := s.db.Model(&PostRef{}).Where("id = ?", pref.ID).Update("thread_size", gorm.Expr("thread_size + 1")).Error; err != nil {
		return err
	}

	return err
}

func (s *Server) indexProfile(ctx context.Context, u *User, rec *bsky.ActorProfile) error {
	n := ""
	if rec.DisplayName != nil {
		n = *rec.DisplayName
	}

	_ = n

	return nil
}

func (s *Server) updateUserHandle(ctx context.Context, did string, handle string) error {
	u, err := s.getOrCreateUser(ctx, did)
	if err != nil {
		return err
	}

	return s.db.Model(&User{}).Where("id = ?", u.ID).Update("handle", handle).Error
}

func (s *Server) handleLike(ctx context.Context, u *User, rec *bsky.FeedLike, path string) error {
	parts := strings.Split(path, "/")

	p, err := s.getPostByUri(ctx, rec.Subject.Uri)
	if err != nil {
		return err
	}

	// TODO: this isnt a scalable way to handle likes, but its the only way
	// right now to ensure that deletes can be correctly processed
	if err := s.db.Create(&FeedLike{
		Uid:  u.ID,
		Rkey: parts[len(parts)-1],
		Ref:  p.ID,
	}).Error; err != nil {
		return err
	}

	if err := s.db.Model(&PostRef{}).Where("id = ?", p.ID).Update("likes", gorm.Expr("likes + 1")).Error; err != nil {
		return err
	}

	// if p.Likes == 11 {
	// 	if err := s.addPostToFeed(ctx, "upandup", p); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func (s *Server) getFeedRef(ctx context.Context, feed string) (*Feed, error) {
	var f Feed
	if err := s.db.First(&f, "name = ?", feed).Error; err != nil {
		return nil, err
	}

	return &f, nil
}

func (s *Server) addPostToFeed(ctx context.Context, feed string, p *PostRef) error {
	f, err := s.getFeedRef(ctx, feed)
	if err != nil {
		return err
	}

	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "feed"}, {Name: "post"}},
		DoNothing: true,
	}).Create(&FeedIncl{
		Post: p.ID,
		Feed: f.ID,
	}).Error; err != nil {
		return err
	}

	return nil
}

func (s *Server) handleRepost(ctx context.Context, u *User, rec *bsky.FeedRepost, path string) error {
	parts := strings.Split(path, "/")

	p, err := s.getPostByUri(ctx, rec.Subject.Uri)
	if err != nil {
		return err
	}

	if err := s.db.Create(&FeedRepost{
		Uid:  u.ID,
		Rkey: parts[len(parts)-1],
		Ref:  p.ID,
	}).Error; err != nil {
		return err
	}

	if err := s.db.Model(&PostRef{}).Where("id = ?", p.ID).Update("reposts", gorm.Expr("reposts + 1")).Error; err != nil {
		return err
	}

	return nil
}

func (s *Server) handleFollow(ctx context.Context, u *User, rec *bsky.GraphFollow, path string) error {
	parts := strings.Split(path, "/")

	target, err := s.getOrCreateUser(ctx, rec.Subject)
	if err != nil {
		return err
	}

	f := &Follow{
		Uid:       u.ID,
		Rkey:      parts[len(parts)-1],
		Following: target.ID,
	}
	if err := s.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "uid"}, {Name: "following"}},
		DoNothing: true,
	}).Create(f).Error; err != nil {
		return err
	}

	return nil
}

func (s *Server) handleBlock(ctx context.Context, u *User, rec *bsky.GraphBlock, path string) error {
	parts := strings.Split(path, "/")

	target, err := s.getOrCreateUser(ctx, rec.Subject)
	if err != nil {
		return err
	}

	if err := s.db.Create(&Block{
		Uid:     u.ID,
		Rkey:    parts[len(parts)-1],
		Blocked: target.ID,
	}).Error; err != nil {
		return err
	}

	return nil
}
