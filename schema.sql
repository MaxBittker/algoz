--
-- PostgreSQL database dump
--

-- Dumped from database version 15.3 (Ubuntu 15.3-0ubuntu0.23.04.1)
-- Dumped by pg_dump version 15.3 (Ubuntu 15.3-0ubuntu0.23.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: bsky; Type: SCHEMA; Schema: -; Owner: bsky
--

CREATE SCHEMA bsky;


ALTER SCHEMA bsky OWNER TO bsky;

--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA bsky;


--
-- Name: EXTENSION vector; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION vector IS 'vector data type and ivfflat access method';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: blocks; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.blocks (
    uid bigint,
    blocked bigint,
    rkey text,
    id integer NOT NULL
);


ALTER TABLE bsky.blocks OWNER TO bsky;

--
-- Name: blocks_temp_id_seq1; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.blocks_temp_id_seq1
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.blocks_temp_id_seq1 OWNER TO bsky;

--
-- Name: blocks_temp_id_seq1; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.blocks_temp_id_seq1 OWNED BY bsky.blocks.id;


--
-- Name: feed_incls; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.feed_incls (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    feed bigint,
    post bigint,
    id integer NOT NULL
);


ALTER TABLE bsky.feed_incls OWNER TO bsky;

--
-- Name: feed_incls_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.feed_incls_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.feed_incls_temp_id_seq OWNER TO bsky;

--
-- Name: feed_incls_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.feed_incls_temp_id_seq OWNED BY bsky.feed_incls.id;


--
-- Name: feed_likes; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.feed_likes (
    uid bigint,
    rkey text,
    ref bigint,
    id integer NOT NULL
);


ALTER TABLE bsky.feed_likes OWNER TO bsky;

--
-- Name: feed_likes_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.feed_likes_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.feed_likes_temp_id_seq OWNER TO bsky;

--
-- Name: feed_likes_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.feed_likes_temp_id_seq OWNED BY bsky.feed_likes.id;


--
-- Name: feed_reposts; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.feed_reposts (
    uid bigint,
    rkey text,
    ref bigint,
    id integer NOT NULL
);


ALTER TABLE bsky.feed_reposts OWNER TO bsky;

--
-- Name: feed_reposts_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.feed_reposts_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.feed_reposts_temp_id_seq OWNER TO bsky;

--
-- Name: feed_reposts_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.feed_reposts_temp_id_seq OWNED BY bsky.feed_reposts.id;


--
-- Name: feeds; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.feeds (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    name text,
    description text,
    id integer NOT NULL
);


ALTER TABLE bsky.feeds OWNER TO bsky;

--
-- Name: feeds_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.feeds_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.feeds_temp_id_seq OWNER TO bsky;

--
-- Name: feeds_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.feeds_temp_id_seq OWNED BY bsky.feeds.id;


--
-- Name: follows; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.follows (
    uid bigint,
    following bigint,
    rkey text,
    id integer NOT NULL
);


ALTER TABLE bsky.follows OWNER TO bsky;

--
-- Name: follows_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.follows_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.follows_temp_id_seq OWNER TO bsky;

--
-- Name: follows_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.follows_temp_id_seq OWNED BY bsky.follows.id;


--
-- Name: images; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.images (
    id integer NOT NULL,
    ref bigint,
    hash character(64),
    embedding bsky.vector(512)
);


ALTER TABLE bsky.images OWNER TO bsky;

--
-- Name: images_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.images_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.images_id_seq OWNER TO bsky;

--
-- Name: images_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.images_id_seq OWNED BY bsky.images.id;


--
-- Name: last_seqs; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.last_seqs (
    seq bigint,
    id integer NOT NULL
);


ALTER TABLE bsky.last_seqs OWNER TO bsky;

--
-- Name: last_seqs_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.last_seqs_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.last_seqs_temp_id_seq OWNER TO bsky;

--
-- Name: last_seqs_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.last_seqs_temp_id_seq OWNED BY bsky.last_seqs.id;


--
-- Name: post_refs; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.post_refs (
    created_at timestamp with time zone,
    cid text,
    rkey text,
    uid bigint,
    not_found boolean,
    likes bigint,
    reposts bigint,
    replies bigint,
    thread_size bigint,
    thread_root bigint,
    reply_to bigint,
    is_reply boolean,
    has_image boolean,
    reposting bigint,
    id integer NOT NULL
);


ALTER TABLE bsky.post_refs OWNER TO bsky;

--
-- Name: post_refs_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.post_refs_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.post_refs_temp_id_seq OWNER TO bsky;

--
-- Name: post_refs_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.post_refs_temp_id_seq OWNED BY bsky.post_refs.id;


--
-- Name: users; Type: TABLE; Schema: bsky; Owner: bsky
--

CREATE TABLE bsky.users (
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
    deleted_at timestamp with time zone,
    did text,
    handle text,
    latest_post bigint,
    blessed boolean,
    blocked boolean,
    scraped_follows boolean,
    id integer NOT NULL
);


ALTER TABLE bsky.users OWNER TO bsky;

--
-- Name: users_temp_id_seq; Type: SEQUENCE; Schema: bsky; Owner: bsky
--

CREATE SEQUENCE bsky.users_temp_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE bsky.users_temp_id_seq OWNER TO bsky;

--
-- Name: users_temp_id_seq; Type: SEQUENCE OWNED BY; Schema: bsky; Owner: bsky
--

ALTER SEQUENCE bsky.users_temp_id_seq OWNED BY bsky.users.id;


--
-- Name: blocks id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.blocks ALTER COLUMN id SET DEFAULT nextval('bsky.blocks_temp_id_seq1'::regclass);


--
-- Name: feed_incls id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_incls ALTER COLUMN id SET DEFAULT nextval('bsky.feed_incls_temp_id_seq'::regclass);


--
-- Name: feed_likes id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_likes ALTER COLUMN id SET DEFAULT nextval('bsky.feed_likes_temp_id_seq'::regclass);


--
-- Name: feed_reposts id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_reposts ALTER COLUMN id SET DEFAULT nextval('bsky.feed_reposts_temp_id_seq'::regclass);


--
-- Name: feeds id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feeds ALTER COLUMN id SET DEFAULT nextval('bsky.feeds_temp_id_seq'::regclass);


--
-- Name: follows id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.follows ALTER COLUMN id SET DEFAULT nextval('bsky.follows_temp_id_seq'::regclass);


--
-- Name: images id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.images ALTER COLUMN id SET DEFAULT nextval('bsky.images_id_seq'::regclass);


--
-- Name: last_seqs id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.last_seqs ALTER COLUMN id SET DEFAULT nextval('bsky.last_seqs_temp_id_seq'::regclass);


--
-- Name: post_refs id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.post_refs ALTER COLUMN id SET DEFAULT nextval('bsky.post_refs_temp_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.users ALTER COLUMN id SET DEFAULT nextval('bsky.users_temp_id_seq'::regclass);


--
-- Name: blocks blocks_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.blocks
    ADD CONSTRAINT blocks_pkey PRIMARY KEY (id);


--
-- Name: feed_incls feed_incls_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_incls
    ADD CONSTRAINT feed_incls_pkey PRIMARY KEY (id);


--
-- Name: feed_likes feed_likes_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_likes
    ADD CONSTRAINT feed_likes_pkey PRIMARY KEY (id);


--
-- Name: feed_reposts feed_reposts_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feed_reposts
    ADD CONSTRAINT feed_reposts_pkey PRIMARY KEY (id);


--
-- Name: feeds feeds_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feeds
    ADD CONSTRAINT feeds_pkey PRIMARY KEY (id);


--
-- Name: follows follows_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.follows
    ADD CONSTRAINT follows_pkey PRIMARY KEY (id);


--
-- Name: feeds idx_feeds_name; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.feeds
    ADD CONSTRAINT idx_feeds_name UNIQUE (name);


--
-- Name: users idx_users_did; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.users
    ADD CONSTRAINT idx_users_did UNIQUE (did);


--
-- Name: images images_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.images
    ADD CONSTRAINT images_pkey PRIMARY KEY (id);


--
-- Name: last_seqs last_seqs_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.last_seqs
    ADD CONSTRAINT last_seqs_pkey PRIMARY KEY (id);


--
-- Name: post_refs post_refs_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.post_refs
    ADD CONSTRAINT post_refs_pkey PRIMARY KEY (id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: bsky; Owner: bsky
--

ALTER TABLE ONLY bsky.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: idx_16392_idx_users_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16392_idx_users_deleted_at ON bsky.users USING btree (deleted_at);


--
-- Name: idx_16392_idx_users_did; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_16392_idx_users_did ON bsky.users USING btree (did);


--
-- Name: idx_16397_idx_follows_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16397_idx_follows_rkey ON bsky.follows USING btree (rkey);


--
-- Name: idx_16397_idx_uid_following; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_16397_idx_uid_following ON bsky.follows USING btree (uid, following);


--
-- Name: idx_16402_idx_post_refs_reply_to; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16402_idx_post_refs_reply_to ON bsky.post_refs USING btree (reply_to);


--
-- Name: idx_16402_idx_post_rkeyuid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_16402_idx_post_rkeyuid ON bsky.post_refs USING btree (rkey, uid);


--
-- Name: idx_16402_idx_post_uid_created; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16402_idx_post_uid_created ON bsky.post_refs USING btree (created_at);


--
-- Name: idx_16402_idx_post_uid_is_reply_created; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16402_idx_post_uid_is_reply_created ON bsky.post_refs USING btree (is_reply);


--
-- Name: idx_16407_idx_feed_incls_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16407_idx_feed_incls_deleted_at ON bsky.feed_incls USING btree (deleted_at);


--
-- Name: idx_16407_idx_feed_post; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_16407_idx_feed_post ON bsky.feed_incls USING btree (feed, post);


--
-- Name: idx_16410_idx_feeds_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16410_idx_feeds_deleted_at ON bsky.feeds USING btree (deleted_at);


--
-- Name: idx_16410_sqlite_autoindex_feeds_1; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_16410_sqlite_autoindex_feeds_1 ON bsky.feeds USING btree (name);


--
-- Name: idx_16415_idx_feed_likes_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16415_idx_feed_likes_rkey ON bsky.feed_likes USING btree (rkey);


--
-- Name: idx_16415_idx_feed_likes_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16415_idx_feed_likes_uid ON bsky.feed_likes USING btree (uid);


--
-- Name: idx_16420_idx_feed_reposts_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16420_idx_feed_reposts_rkey ON bsky.feed_reposts USING btree (rkey);


--
-- Name: idx_16420_idx_feed_reposts_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16420_idx_feed_reposts_uid ON bsky.feed_reposts USING btree (uid);


--
-- Name: idx_16425_idx_blocks_blocked; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16425_idx_blocks_blocked ON bsky.blocks USING btree (blocked);


--
-- Name: idx_16425_idx_blocks_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16425_idx_blocks_rkey ON bsky.blocks USING btree (rkey);


--
-- Name: idx_16425_idx_blocks_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_16425_idx_blocks_uid ON bsky.blocks USING btree (uid);


--
-- Name: idx_blocks_blocked; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_blocks_blocked ON bsky.blocks USING btree (blocked);


--
-- Name: idx_blocks_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_blocks_rkey ON bsky.blocks USING btree (rkey);


--
-- Name: idx_blocks_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_blocks_uid ON bsky.blocks USING btree (uid);


--
-- Name: idx_feed_incls_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feed_incls_deleted_at ON bsky.feed_incls USING btree (deleted_at);


--
-- Name: idx_feed_likes_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feed_likes_rkey ON bsky.feed_likes USING btree (rkey);


--
-- Name: idx_feed_likes_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feed_likes_uid ON bsky.feed_likes USING btree (uid);


--
-- Name: idx_feed_post; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_feed_post ON bsky.feed_incls USING btree (feed, post);


--
-- Name: idx_feed_reposts_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feed_reposts_rkey ON bsky.feed_reposts USING btree (rkey);


--
-- Name: idx_feed_reposts_uid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feed_reposts_uid ON bsky.feed_reposts USING btree (uid);


--
-- Name: idx_feeds_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_feeds_deleted_at ON bsky.feeds USING btree (deleted_at);


--
-- Name: idx_follows_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_follows_rkey ON bsky.follows USING btree (rkey);


--
-- Name: idx_follows_uid_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_follows_uid_rkey ON bsky.follows USING btree (uid, rkey);


--
-- Name: idx_post_refs_reply_to; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_post_refs_reply_to ON bsky.post_refs USING btree (reply_to);


--
-- Name: idx_post_rkeyuid; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_post_rkeyuid ON bsky.post_refs USING btree (rkey, uid);


--
-- Name: idx_post_uid_created; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_post_uid_created ON bsky.post_refs USING btree (created_at);


--
-- Name: idx_post_uid_is_reply_created; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_post_uid_is_reply_created ON bsky.post_refs USING btree (is_reply);


--
-- Name: idx_post_uid_is_reply_created_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_post_uid_is_reply_created_at ON bsky.post_refs USING btree (uid, is_reply, created_at DESC);


--
-- Name: idx_post_uid_rkey; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_post_uid_rkey ON bsky.post_refs USING btree (uid, rkey);


--
-- Name: idx_uid_following; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE UNIQUE INDEX idx_uid_following ON bsky.follows USING btree (uid, following);


--
-- Name: idx_users_deleted_at; Type: INDEX; Schema: bsky; Owner: bsky
--

CREATE INDEX idx_users_deleted_at ON bsky.users USING btree (deleted_at);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

