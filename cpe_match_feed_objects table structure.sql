--
-- Type: TABLE ; Name: cpe_match_feed_objects; Owner: postgres
--

CREATE TABLE cpe_match_feed_objects (
    id integer NOT NULL,
    vendor character varying NOT NULL,
    product character varying NOT NULL,
    version character varying,
    "update" character varying,
    edition character varying,
    language character varying,
    swedition character varying,
    targetsw character varying,
    targethw character varying,
    other character varying,
    timestamp timestamptz NOT NULL DEFAULT now()
);

CREATE SEQUENCE cpe_match_feed_objects_id_seq;

ALTER TABLE public.cpe_match_feed_objects ALTER id SET DEFAULT nextval('cpe_match_feed_objects_id_seq'::regclass);

ALTER TABLE cpe_match_feed_objects ADD CONSTRAINT cpe_match_feed_objects_pkey
  PRIMARY KEY (id);
  
CREATE INDEX cpe_match_feed_objects_vendor_product_idx ON public.cpe_match_feed_objects 
  USING btree (vendor, product);

ALTER TABLE cpe_match_feed_objects OWNER TO postgres;





--
-- Type: MATERIALIZED VIEW ; Name: products; Owner: postgres
--
CREATE MATERIALIZED VIEW products AS
 SELECT cpe_match_feed_objects.vendor,
    cpe_match_feed_objects.product,
    count(*) AS versions
   FROM cpe_match_feed_objects
  GROUP BY cpe_match_feed_objects.vendor, cpe_match_feed_objects.product;


ALTER MATERIALIZED VIEW products OWNER TO postgres;

-- REFRESH MATERIALIZED VIEW products;

-- SELECT t.vendor
--      , t.product
--      , t.versions
--  FROM public.products t
-- WHERE product ilike '%Windows%'

-- SELECT *
--  FROM public.cpe_match_feed_objects t
-- WHERE product ilike '%Windows%'
-- ORDER BY version;

