package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	api "github.com/bluesky-social/indigo/api"
	"github.com/bluesky-social/indigo/api/atproto"
	comatproto "github.com/bluesky-social/indigo/api/atproto"
	bsky "github.com/bluesky-social/indigo/api/bsky"
	cliutil "github.com/bluesky-social/indigo/cmd/gosky/util"
	"github.com/bluesky-social/indigo/did"
	"github.com/bluesky-social/indigo/events"
	lexutil "github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/repo"
	"github.com/bluesky-social/indigo/repomgr"
	"github.com/bluesky-social/indigo/util"
	"github.com/bluesky-social/indigo/xrpc"
	"github.com/gorilla/websocket"
	lru "github.com/hashicorp/golang-lru"
	"github.com/ipfs/go-cid"
	logging "github.com/ipfs/go-log"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	. "github.com/whyrusleeping/algoz/models"

	cli "github.com/urfave/cli/v2"

	gorm "gorm.io/gorm"
	"gorm.io/gorm/clause"
)

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

	userLk    sync.Mutex
	userCache *lru.Cache
	keyCache  *lru.Cache
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
			Name:    "readonly",
			EnvVars: []string{"READONLY"},
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

		s.pollAllUsersFollows(context.Background())

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

func (s *Server) AddProcessor(p Processor) {
	s.processors = append(s.processors, p)
}

// type cachedKey struct {
// 	EOL time.Time
// 	Key any
// }

// func (s *Server) getKeyForDid(did string) (any, error) {
// 	doc, err := s.didr.GetDocument(context.TODO(), did)
// 	if err != nil {
// 		return nil, err
// 	}

// 	pubk, err := doc.GetPublicKey("#atproto")
// 	if err != nil {
// 		return nil, err
// 	}

// 	switch pubk.Type {
// 	case "EcdsaSecp256k1VerificationKey2019":
// 		pub, err := secp256k1.ParsePubKey(pubk.Raw.([]byte))
// 		if err != nil {
// 			return nil, fmt.Errorf("pubkey was invalid: %w", err)
// 		}

// 		ecp := pub.ToECDSA()

// 		return ecp, nil
// 	default:
// 		return nil, fmt.Errorf("unrecognized key type: %q", pubk.Type)

// 	}

// }

// func (s *Server) fetchKey(tok *jwt.Token) (any, error) {
// 	issuer, ok := tok.Claims.(jwt.MapClaims)["iss"].(string)
// 	if !ok {
// 		return nil, fmt.Errorf("missing 'iss' field from auth header")
// 	}

// 	val, ok := s.keyCache.Get(issuer)
// 	if ok {
// 		ck := val.(*cachedKey)
// 		if time.Now().Before(ck.EOL) {
// 			return ck.Key, nil
// 		}
// 	}

// 	k, err := s.getKeyForDid(issuer)
// 	if err != nil {
// 		return nil, err
// 	}

// 	s.keyCache.Add(issuer, &cachedKey{
// 		EOL: time.Now().Add(time.Minute * 10),
// 		Key: k,
// 	})

// 	return k, nil
// }

type FeedItem struct {
	Post string `json:"post"`
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
func (s *Server) updateUserHandle(ctx context.Context, did string, handle string) error {
	u, err := s.getOrCreateUser(ctx, did)
	if err != nil {
		return err
	}

	return s.db.Model(&User{}).Where("id = ?", u.ID).Update("handle", handle).Error
}

func (s *Server) deletePost(ctx context.Context, u *User, path string) error {
	log.Debugf("deleting post: %s", path)

	// TODO:
	return nil
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

func (s *Server) getLastCursor() (int64, error) {
	var lastSeq LastSeq
	if err := s.db.Find(&lastSeq).Error; err != nil {
		return 0, err
	}

	if lastSeq.ID == 0 {
		return 0, s.db.Create(&lastSeq).Error
	}

	return lastSeq.Seq, nil
}

func (s *Server) updateLastCursor(curs int64) error {
	return s.db.Model(LastSeq{}).Where("id = 1").Update("seq", curs).Error
}

func (s *Server) Run(ctx context.Context) error {
	cur, err := s.getLastCursor()
	if err != nil {
		return fmt.Errorf("get last cursor: %w", err)
	}

	pool := events.NewConsumerPool(16, 32, func(ctx context.Context, xe *events.XRPCStreamEvent) error {
		switch {
		case xe.RepoCommit != nil:
			evt := xe.RepoCommit
			if evt.TooBig && evt.Prev != nil {
				log.Errorf("skipping non-genesis too big events for now: %d", evt.Seq)
				return nil
			}

			if evt.TooBig {
				if err := s.processTooBigCommit(ctx, evt); err != nil {
					log.Errorf("failed to process tooBig event: %s", err)
					return nil
				}

				return nil
			}

			r, err := repo.ReadRepoFromCar(ctx, bytes.NewReader(evt.Blocks))
			if err != nil {
				log.Errorf("reading repo from car (seq: %d, len: %d): %w", evt.Seq, len(evt.Blocks), err)
				return nil
			}

			for _, op := range evt.Ops {
				ek := repomgr.EventKind(op.Action)
				switch ek {
				case repomgr.EvtKindCreateRecord, repomgr.EvtKindUpdateRecord:
					rc, rec, err := r.GetRecord(ctx, op.Path)
					if err != nil {
						e := fmt.Errorf("getting record %s (%s) within seq %d for %s: %w", op.Path, *op.Cid, evt.Seq, evt.Repo, err)
						log.Error(e)
						return nil
					}

					if lexutil.LexLink(rc) != *op.Cid {
						log.Errorf("mismatch in record and op cid: %s != %s", rc, *op.Cid)
						return nil
					}

					if err := s.handleOp(ctx, ek, evt.Seq, op.Path, evt.Repo, &rc, rec); err != nil {
						log.Errorf("failed to handle op: %s", err)
						return nil
					}

				case repomgr.EvtKindDeleteRecord:
					if err := s.handleOp(ctx, ek, evt.Seq, op.Path, evt.Repo, nil, nil); err != nil {
						// log.Errorf("failed to handle delete: %s", err)
						return nil
					}
				}
			}

			return nil
		case xe.RepoHandle != nil:
			evt := xe.RepoHandle
			if err := s.updateUserHandle(ctx, evt.Did, evt.Handle); err != nil {
				log.Errorf("failed to update user handle: %s", err)
			}
			return nil
		default:
			return nil
		}
	})

	var backoff time.Duration
	for {
		d := websocket.DefaultDialer
		con, _, err := d.Dial(fmt.Sprintf("%s/xrpc/com.atproto.sync.subscribeRepos?cursor=%d", s.bgshost, cur), http.Header{})
		if err != nil {
			log.Errorf("failed to dial: %s", err)
			time.Sleep(backoff)

			backoff = (backoff * 2) + time.Second
			if backoff > time.Minute*2 {
				return fmt.Errorf("failed to dial for a long time")
			}
			continue
		}

		backoff = 0

		if err := events.HandleRepoStream(ctx, con, pool); err != nil {
			log.Errorf("stream processing error: %s", err)

		}
	}
}

// handleOp receives every incoming repo event and is where indexing logic lives
func (s *Server) handleOp(ctx context.Context, op repomgr.EventKind, seq int64, path string, did string, rcid *cid.Cid, rec any) error {
	if op == repomgr.EvtKindCreateRecord || op == repomgr.EvtKindUpdateRecord {
		log.Debugf("handling event(%d): %s - %s", seq, did, path)
		u, err := s.getOrCreateUser(ctx, did)
		if err != nil {
			return fmt.Errorf("checking user: %w", err)
		}
		switch rec := rec.(type) {
		case *bsky.FeedPost:
			// if err := s.indexPost(ctx, u, rec, path, *rcid); err != nil {
			// 	return fmt.Errorf("indexing post: %w", err)
			// }
		case *bsky.ActorProfile:
			// if err := s.indexProfile(ctx, u, rec); err != nil {
			// 	return fmt.Errorf("indexing profile: %w", err)
			// }
		case *bsky.FeedLike:
			// if err := s.handleLike(ctx, u, rec, path); err != nil {
			// 	return fmt.Errorf("handling like: %w", err)
			// }
		case *bsky.FeedRepost:
			// if err := s.handleRepost(ctx, u, rec, path); err != nil {
			// 	return fmt.Errorf("handling repost: %w", err)
			// }
		case *bsky.GraphFollow:
			if err := s.handleFollow(ctx, u, rec, path); err != nil {
				return fmt.Errorf("handling repost: %w", err)
			}
		case *bsky.GraphBlock:
			// if err := s.handleBlock(ctx, u, rec, path); err != nil {
			// 	return fmt.Errorf("handling repost: %w", err)
			// }
		default:
		}

	} else if op == repomgr.EvtKindDeleteRecord {
		u, err := s.getOrCreateUser(ctx, did)
		if err != nil {
			return err
		}

		parts := strings.Split(path, "/")
		// Not handling like/repost deletes because it requires individually tracking *every* single like
		switch parts[0] {
		// TODO: handle profile deletes, its an edge case, but worth doing still
		case "app.bsky.feed.post":
			if err := s.deletePost(ctx, u, path); err != nil {
				return err
			}
		case "app.bsky.feed.like":
			// if err := s.deleteLike(ctx, u, path); err != nil {
			// 	return err
			// }
		case "app.bsky.feed.repost":
			if err := s.deleteRepost(ctx, u, path); err != nil {
				return err
			}
		case "app.bsky.graph.follow":
			if err := s.deleteFollow(ctx, u, path); err != nil {
				return err
			}
		}
	}

	if seq%50 == 0 {
		if err := s.updateLastCursor(seq); err != nil {
			log.Error("Failed to update cursor: ", err)
		}
	}

	return nil
}

func (s *Server) processTooBigCommit(ctx context.Context, evt *comatproto.SyncSubscribeRepos_Commit) error {
	repodata, err := comatproto.SyncGetRepo(ctx, s.bgsxrpc, evt.Repo, "", evt.Commit.String())
	if err != nil {
		return err
	}

	r, err := repo.ReadRepoFromCar(ctx, bytes.NewReader(repodata))
	if err != nil {
		return err
	}

	u, err := s.getOrCreateUser(ctx, evt.Repo)
	if err != nil {
		return err
	}

	return r.ForEach(ctx, "", func(k string, v cid.Cid) error {
		rcid, rec, err := r.GetRecord(ctx, k)
		if err != nil {
			log.Errorf("failed to get record from repo checkout: %s", err)
			return nil
		}

		return s.handleOp(ctx, repomgr.EvtKindCreateRecord, evt.Seq, k, u.Did, &rcid, rec)
	})
}

func (s *Server) getOrCreateUser(ctx context.Context, did string) (*User, error) {
	s.userLk.Lock()
	cu, ok := s.userCache.Get(did)
	if ok {
		s.userLk.Unlock()
		u := cu.(*User)
		u.Lk.Lock()
		u.Lk.Unlock()
		if u.ID == 0 {
			return nil, fmt.Errorf("user creation failed")
		}

		return cu.(*User), nil
	}

	var u User
	s.userCache.Add(did, &u)

	u.Lk.Lock()
	defer u.Lk.Unlock()
	s.userLk.Unlock()

	if err := s.db.Find(&u, "did = ?", did).Error; err != nil {
		return nil, err
	}
	if u.ID == 0 {
		// TODO: figure out peoples handles
		h, err := s.handleFromDid(ctx, did)
		if err != nil {
			log.Errorw("failed to resolve did to handle", "did", did, "err", err)
		} else {
			u.Handle = h
		}

		u.Did = did
		if err := s.db.Create(&u).Error; err != nil {
			s.userCache.Remove(did)

			return nil, err
		}
	}

	return &u, nil
}

func (s *Server) handleFromDid(ctx context.Context, did string) (string, error) {
	handle, _, err := api.ResolveDidToHandle(ctx, s.xrpcc, s.didr, &api.ProdHandleResolver{}, did)
	if err != nil {
		return "", err
	}

	return handle, nil
}
