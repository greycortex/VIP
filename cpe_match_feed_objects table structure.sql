--
-- Type: TABLE ; Name: cpe; Owner: postgres
--

CREATE TABLE cpe (
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

CREATE SEQUENCE cpe_id_seq;

ALTER TABLE public.cpe ALTER id SET DEFAULT nextval('cpe_id_seq'::regclass);

ALTER TABLE cpe ADD CONSTRAINT cpe_pkey
  PRIMARY KEY (id);
  
CREATE INDEX cpe_vendor_product_idx ON public.cpe
  USING btree (vendor, product);

ALTER TABLE cpe OWNER TO postgres;


--
-- Type: MATERIALIZED VIEW ; Name: products; Owner: postgres
--
CREATE MATERIALIZED VIEW products AS
 SELECT cpe.vendor,
    cpe.product,
    count(*) AS versions
   FROM cpe
  GROUP BY cpe.vendor, cpe.product;


ALTER MATERIALIZED VIEW products OWNER TO postgres;

-- REFRESH MATERIALIZED VIEW products;

-- SELECT t.vendor
--      , t.product
--      , t.versions
--  FROM public.products t
-- WHERE product ilike '%Windows%'

-- SELECT *
--  FROM public.cpe t
-- WHERE product ilike '%Windows%'
-- ORDER BY version;


-- NEW INSERT (when needed an ID)
-- WITH t AS (
--     INSERT INTO cpe (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other)
--              VALUES ('GreyCortex', 'VIP', '0.0devel', null, null, null, null, null, null, null)
--     RETURNING *
-- )
-- SELECT t.id FROM t;