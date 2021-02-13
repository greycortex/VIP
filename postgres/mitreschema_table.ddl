CREATE TABLE CVEobject (
  Meta_data_id       varchar(63) NOT NULL,
  CVSS3objectID      int8 NOT NULL, 
  CVSS2objectID      int8 NOT NULL, 
  Data_type          varchar(255) NOT NULL, 
  Data_format        varchar(255) NOT NULL, 
  Data_version       varchar(255) NOT NULL, 
  Meta_data_assigner varchar(255) NOT NULL, 
  Descriptions       varchar(255)[] NOT NULL,
  Cve_data_version   varchar(255) NOT NULL, 
  Cvss_v2_base_score float8 NOT NULL, 
  Cvss_v3_base_score float8 NOT NULL, 
  Published_date     date NOT NULL, 
  Last_modified_date date NOT NULL);
CREATE TABLE CVSS3object (
  ID                      BIGSERIAL NOT NULL, 
  Version                 varchar(255) NOT NULL, 
  Vector_string           varchar(255) NOT NULL, 
  Attack_vector           varchar(255) NOT NULL, 
  Attack_complexity       varchar(255) NOT NULL, 
  Privileges_required     varchar(255) NOT NULL, 
  User_interaction        varchar(255) NOT NULL, 
  Scope                   varchar(255) NOT NULL, 
  Confidentiality_impact  varchar(255) NOT NULL, 
  Integrity_impact        varchar(255) NOT NULL, 
  Availability_impact     varchar(255) NOT NULL, 
  Base_score_v3           float8 NOT NULL, 
  Base_severity_v3        varchar(255) NOT NULL, 
  Exploitability_score_v3 float8 NOT NULL, 
  Impact_score_v3         float8 NOT NULL);
CREATE TABLE CVSS2object (
  ID                        BIGSERIAL NOT NULL, 
  Version                   varchar(255), 
  Vector_string             varchar(255) NOT NULL, 
  Access_vector             varchar(255) NOT NULL, 
  Access_complexity         varchar(255) NOT NULL, 
  Authentication            varchar(255) NOT NULL, 
  Confidentiality_impact    varchar(255) NOT NULL, 
  Integrity_impact          varchar(255) NOT NULL, 
  Availability_impact       varchar(255) NOT NULL, 
  Base_score_v2             float8 NOT NULL, 
  Severity                  varchar(255) NOT NULL, 
  Exploitability_score_v2   float8 NOT NULL, 
  Impact_score_v2           float8 NOT NULL, 
  Ac_insuf_info             varchar(255), 
  Obtain_all_privilege      varchar(255), 
  Obtain_user_privilege     varchar(255), 
  Obtain_other_privilege    varchar(255), 
  User_interaction_required varchar(255));
CREATE TABLE CWEobject (
  code_id               varchar(63) NOT NULL, 
  CVEobjectMeta_data_id varchar(63) NOT NULL, 
  Name                  varchar(255) NOT NULL, 
  Abstraction           varchar(255) NOT NULL, 
  Structure             varchar(255) NOT NULL, 
  Status                varchar(255) NOT NULL, 
  Description           varchar(255) NOT NULL, 
  Ext_description       varchar(255), 
  Exploit_likelihood    varchar(255), 
  Bg_details            varchar(255)[],
  Rel_attack_patterns   varchar(63)[],
  Affected_resources    varchar(255)[],
  Functional_areas      varchar(255)[]);
CREATE TABLE CWErelationObj (
  ID               BIGSERIAL NOT NULL, 
  CWEobjectcode_id varchar(63) NOT NULL, 
  Nature           varchar(255) NOT NULL, 
  Related_cwe_id   varchar(255) NOT NULL, 
  View_id          varchar(255) NOT NULL, 
  Ordinal          varchar(255));
CREATE TABLE CWEapplPlatfObj (
  ID               BIGSERIAL NOT NULL, 
  CWEobjectcode_id varchar(63) NOT NULL, 
  Type             varchar(255) NOT NULL, 
  Platform_class   varchar(255), 
  Name             varchar(255), 
  Prevalence       varchar(255) NOT NULL);
CREATE TABLE CWEnoteObj (
  ID                        BIGSERIAL NOT NULL, 
  CWEcategoryObjCategory_id int8, 
  CWEobjectcode_id          varchar(63), 
  CWEviewObjView_id         varchar(63), 
  CAPECobjectCapec_id       varchar(63), 
  Type                      varchar(255) NOT NULL, 
  Note_content              varchar(255) NOT NULL);
CREATE TABLE CWEcategoryObj (
  Category_id      int8 NOT NULL, 
  Category_name    varchar(255) NOT NULL, 
  Category_status  varchar(255) NOT NULL, 
  Category_summary varchar(255) NOT NULL);
CREATE TABLE CWErelationshipObj (
  ID                        BIGSERIAL NOT NULL, 
  CWEcategoryObjCategory_id int8, 
  CWEviewObjView_id         varchar(63), 
  Cwe_id                    varchar(255), 
  View_id                   varchar(255), 
  Capec_id                  varchar(255));
CREATE TABLE CWEviewObj (
  View_id        varchar(63) NOT NULL, 
  View_name      varchar(255) NOT NULL, 
  View_type      varchar(255) NOT NULL, 
  View_status    varchar(255) NOT NULL, 
  View_objective varchar(255) NOT NULL, 
  View_filter    varchar(255));
CREATE TABLE CWEextRefRefObj (
  ID                        BIGSERIAL NOT NULL, 
  Ext_ref_id                varchar(63) NOT NULL, 
  CWEcategoryObjCategory_id int8, 
  CWEobjectcode_id          varchar(63), 
  CWEviewObjView_id         varchar(63), 
  CWEdemExObjID             int8, 
  CAPECobjectCapec_id       varchar(63), 
  Section                   varchar(255));
CREATE TABLE CWEextRefObj (
  Reference_id      varchar(63) NOT NULL, 
  Title             varchar(255) NOT NULL, 
  Url               varchar(255), 
  Publication       varchar(255), 
  Publisher         varchar(255), 
  Edition           varchar(255), 
  Authors           varchar(255)[],
  Publication_date  date, 
  Url_date          date, 
  CWEextRefRefObjID varchar(63));
CREATE TABLE CWEdemExObj (
  ID                BIGSERIAL NOT NULL, 
  CWEobjectcode_id  varchar(63) NOT NULL, 
  Intro_text        varchar(255) NOT NULL, 
  Dem_ex_body_texts varchar(255)[]);
CREATE TABLE CWEexampCodeObj (
  ID            BIGSERIAL NOT NULL, 
  CWEdemExObjID int8 NOT NULL, 
  Nature        varchar(255) NOT NULL, 
  Language      varchar(255), 
  Content       varchar(255));
CREATE TABLE CAPECobject (
  Capec_id          varchar(63) NOT NULL, 
  Capec_name        varchar(255) NOT NULL, 
  Capec_abstraction varchar(255) NOT NULL, 
  Capec_status      varchar(255) NOT NULL, 
  Description       varchar(255) NOT NULL, 
  Attack_likelihood varchar(255), 
  Typical_severity  varchar(255), 
  Rel_cwe_ids       varchar(63)[],
  Mitigations       varchar(255)[],
  Prerequisites     varchar(255)[],
  Examples          varchar(255)[],
  Resources         varchar(255)[],
  Indicators        varchar(255)[]);
CREATE TABLE CWEtaxMapObj (
  ID                        BIGSERIAL NOT NULL, 
  CWEcategoryObjCategory_id int8, 
  CWEobjectcode_id          varchar(63), 
  CAPECobjectCapec_id       varchar(63), 
  Name                      varchar(255) NOT NULL, 
  Entry_name                varchar(255), 
  Entry_id                  varchar(255), 
  Mapping_fit               varchar(255));
CREATE TABLE CWEalterTermObj (
  ID                  BIGSERIAL NOT NULL, 
  CWEobjectcode_id    varchar(63), 
  CAPECobjectCapec_id varchar(63), 
  Term                varchar(255) NOT NULL, 
  Description         varchar(255));
CREATE TABLE CWEconseqObj (
  ID                  BIGSERIAL NOT NULL, 
  CWEobjectcode_id    varchar(63), 
  CAPECobjectCapec_id varchar(63), 
  Scopes              varchar(255)[] NOT NULL,
  Impacts             varchar(255)[] NOT NULL,
  Notes               varchar(255)[],
  Likelihoods         varchar(255)[]);
CREATE TABLE CAPECattStepObj (
  ID                  BIGSERIAL NOT NULL, 
  CAPECobjectCapec_id varchar(63) NOT NULL, 
  Step                varchar(255) NOT NULL, 
  Phase               varchar(255) NOT NULL, 
  Description         varchar(255) NOT NULL, 
  Techniques          varchar(255)[]);
CREATE TABLE CAPECrelationObj (
  ID                  BIGSERIAL NOT NULL, 
  CAPECobjectCapec_id varchar(63) NOT NULL, 
  Nature              varchar(255) NOT NULL, 
  Related_capec_id    varchar(255) NOT NULL, 
  Exclude_ids         varchar(63)[]);
CREATE TABLE CAPECskillObj (
  ID                  BIGSERIAL NOT NULL, 
  CAPECobjectCapec_id varchar(63) NOT NULL, 
  Level               varchar(255) NOT NULL, 
  Content             varchar(255) NOT NULL);
CREATE TABLE CWEstakeholderObj (
  ID                BIGSERIAL NOT NULL, 
  CWEviewObjView_id varchar(63) NOT NULL, 
  Type              varchar(255) NOT NULL, 
  Description       varchar(255));
CREATE TABLE CWEintrModesObj (
  ID               BIGSERIAL NOT NULL, 
  CWEobjectcode_id varchar(63) NOT NULL, 
  Phase            varchar(255) NOT NULL, 
  Note             varchar(255));
CREATE TABLE CWEpotMitObj (
  Mitigation_id       varchar(63) NOT NULL, 
  CWEobjectcode_id    varchar(63) NOT NULL, 
  Phases              varchar(255)[] NOT NULL,
  Strategy            varchar(255), 
  Description         varchar(255) NOT NULL, 
  Effectiveness       varchar(255), 
  Effectiveness_notes varchar(255));
CREATE TABLE CWEweakOrdObj (
  ID               BIGSERIAL NOT NULL, 
  CWEobjectcode_id varchar(63) NOT NULL, 
  Ordinality       varchar(255) NOT NULL, 
  Description      varchar(255));
CREATE TABLE CWEobsExObj (
  ID               BIGSERIAL NOT NULL, 
  CWEobjectcode_id varchar(63) NOT NULL, 
  Reference        varchar(255) NOT NULL, 
  Description      varchar(255) NOT NULL, 
  Link             varchar(255) NOT NULL);
CREATE TABLE CWEdetMethObj (
  Method_id           varchar(63) NOT NULL, 
  CWEobjectcode_id    varchar(63) NOT NULL, 
  Method              varchar(255) NOT NULL, 
  Description         varchar(255) NOT NULL, 
  Effectiveness       varchar(255), 
  Effectiveness_notes varchar(255));
CREATE TABLE ReferenceObject (
  ID                    BIGSERIAL NOT NULL, 
  CVEobjectMeta_data_id varchar(63) NOT NULL, 
  Url                   varchar(255), 
  Name                  varchar(255), 
  Refsource             varchar(255), 
  Tags                  varchar(255)[]);
CREATE TABLE CPEnodeObject (
  ID                    BIGSERIAL NOT NULL, 
  CVEobjectMeta_data_id varchar(63) NOT NULL, 
  Complex_cpe_objs      int8[] NOT NULL,
  Operators             varchar(63)[] NOT NULL,
  counts                int4[] NOT NULL);
CREATE TABLE CPEobject (
  ID                      BIGSERIAL NOT NULL, 
  Vendor                  varchar(255) NOT NULL, 
  Product                 varchar(255) NOT NULL, 
  Version                 varchar(255), 
  "Update"                varchar(255), 
  Edition                 varchar(255), 
  Language                varchar(255), 
  SwEdition               varchar(255), 
  TargetSw                varchar(255), 
  TargetHw                varchar(255), 
  Other                   varchar(255), 
  Vulnerable              bool, 
  Version_start_excluding varchar(255), 
  Version_end_excluding   varchar(255), 
  Version_start_including varchar(255), 
  Version_end_including   varchar(255), 
  Discriminator           varchar(255));
CREATE TABLE CPEnodeObject_CPEobject (
  CPEobjectID     int8 NOT NULL, 
  CPEnodeObjectID int8 NOT NULL);
