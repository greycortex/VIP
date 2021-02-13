--
-- Type: TABLE ; Name: mitre.cpeobject; Owner: postgres
--

--CREATE TABLE cpeobject (
--    id integer NOT NULL,
--    vendor character varying NOT NULL,
--    product character varying NOT NULL,
--    version character varying,
--    "update" character varying,
--    edition character varying,
--    language character varying,
--    swedition character varying,
--    targetsw character varying,
--    targethw character varying,
--    other character varying,
--    timestamp timestamptz NOT NULL DEFAULT now()
--);

--CREATE SEQUENCE cpe_id_seq;

ALTER TABLE public.cpeobjectLTER id SET DEFAULT nextval('cpe_id_seq'::regclass);

ALTER TABLE cpeobject ADD CONSTRAINT cpeobject_pkey
  PRIMARY KEY (id);
  
CREATE INDEX cpe_vendor_product_idx ON public.cpeobject
  USING btree (vendor, product);

ALTER TABLE cpeobject OWNER TO postgres;


--
-- Type: MATERIALIZED VIEW ; Name: products; Owner: postgres
--
CREATE MATERIALIZED VIEW products AS
 SELECT cpeobject.vendor,
    cpeobject.product,
    count(*) AS versions
   FROM cpeobject
  GROUP BY cpeobject.vendor, cpeobject.product;


ALTER MATERIALIZED VIEW products OWNER TO postgres;

-- REFRESH MATERIALIZED VIEW products;

-- SELECT t.vendor
--      , t.product
--      , t.versions
--  FROM public.products t
-- WHERE product ilike '%Windows%'

-- SELECT *
--  FROM public.mitre.cpe t
-- WHERE product ilike '%Windows%'
-- ORDER BY version;


-- NEW INSERT (when needed an ID)
-- WITH t AS (
--     INSERT INTO mitre.cpe (vendor, product, version, update, edition, language, swedition, targetsw, targethw, other)
--              VALUES ('GreyCortex', 'VIP', '0.0devel', null, null, null, null, null, null, null)
--     RETURNING *
-- )
-- SELECT t.id FROM t;