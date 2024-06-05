/*********
Snowflake Data Masking based on Security Clearance Level
Acompanyng script for blog https://medium.com/@aswinee.rath/snowflake-data-masking-based-on-security-clearance-level-b98e74484506
**********/


/*********
Step 1: Design the base RBAC
**********/

/*******
Create a Sample database.
********/

-- Create DB, Schema, Warehouse
USE ROLE SYSADMIN;
--create a database
create database demo_db;
--lets create a  schema to hold our PII data
CREATE SCHEMA TAG_BASED_MASKING_DEMO;
--create a warehouse for this exmaple
--we can use an existing warehouse too
CREATE OR REPLACE WAREHOUSE demo_build_wh WITH WAREHOUSE_SIZE='X-SMALL';
--set the context for rest of the script
use DATABASE demo_db;
use schema TAG_BASED_MASKING_DEMO;
use warehouse demo_build_wh;

/**********
Setup Functional Roles
***********/

-- Create Roles
USE ROLE USERADMIN;
CREATE ROLE DEVELOPER;
CREATE ROLE ANALYST;
CREATE ROLE SUPPORT;
CREATE ROLE REPORTING;
CREATE ROLE TAG_ADMIN;

-- For this demo, grant sysadmin the above roles
-- so we can change role to test and apply tags
GRANT ROLE DEVELOPER TO ROLE SYSADMIN;
GRANT ROLE ANALYST TO ROLE SYSADMIN;
GRANT ROLE SUPPORT TO ROLE SYSADMIN;
GRANT ROLE REPORTING TO ROLE SYSADMIN;
GRANT ROLE TAG_ADMIN TO ROLE SYSADMIN;

--warehouse permission
use role sysadmin;
GRANT USAGE ON WAREHOUSE DEMO_BUILD_WH TO ROLE DEVELOPER;
GRANT USAGE ON WAREHOUSE DEMO_BUILD_WH TO ROLE ANALYST;
GRANT USAGE ON WAREHOUSE DEMO_BUILD_WH TO ROLE SUPPORT;
GRANT USAGE ON WAREHOUSE DEMO_BUILD_WH TO ROLE REPORTING;

/***************
Setup Discretionary Role and Map to Functional Roles
***************/


-- create discretionary roles
USE ROLE useradmin;
CREATE ROLE read_write;
CREATE ROLE read_only;

--map discretionary to functional roles
-- Grants for hierarchy
use role securityadmin;
--every one except SUPPORT has read access
GRANT ROLE read_only TO ROLE  DEVELOPER; 
GRANT ROLE read_only  TO ROLE REPORTING; 
GRANT ROLE read_only  TO ROLE ANALYST; 

--grant read write to support/ data ingestion roles
GRANT ROLE read_write  TO ROLE SUPPORT;

-- Grant privileges
use role securityadmin;
GRANT USAGE ON DATABASE DEMO_DB TO ROLE read_only;
GRANT USAGE ON SCHEMA DEMO_DB.TAG_BASED_MASKING_DEMO TO ROLE read_only;

GRANT USAGE ON DATABASE DEMO_DB TO ROLE read_write;
GRANT USAGE ON SCHEMA DEMO_DB.TAG_BASED_MASKING_DEMO TO ROLE read_write;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE read_write;
GRANT SELECT ON ALL TABLES IN SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE read_only;

--future grants
GRANT SELECT, INSERT, UPDATE, DELETE ON future TABLES IN SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE read_write;
GRANT SELECT ON future TABLES IN SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE read_only;


/***********
Step 2: Create a TAG Admin
*************/

-- Grants to create and apply tags + apply masking policy to TAG_ADMIN role
USE ROLE ACCOUNTADMIN; // can use SECURITYADMIN role as well
GRANT APPLY TAG ON ACCOUNT TO ROLE TAG_ADMIN;
GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE TAG_ADMIN;

--allow TAG_ADMIN to create TAGs in our demo schema
use role sysadmin;
GRANT USAGE ON DATABASE demo_db TO ROLE TAG_ADMIN;
GRANT USAGE ON SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE TAG_ADMIN;
GRANT CREATE TAG ON SCHEMA demo_db.TAG_BASED_MASKING_DEMO TO ROLE TAG_ADMIN;

/**************
Step 3: Setup Users and Map the Functional Roles
***************/

-- create users
use role useradmin;
CREATE USER john PASSWORD='abc123' MUST_CHANGE_PASSWORD = TRUE;
CREATE USER jack PASSWORD='abc123' MUST_CHANGE_PASSWORD = TRUE;
CREATE USER jane PASSWORD='abc123' MUST_CHANGE_PASSWORD = TRUE;
CREATE USER jill PASSWORD='abc123' MUST_CHANGE_PASSWORD = TRUE;

--grant roles to the user
grant role analyst to user john;
grant role developer to user jack;
grant role analyst to user jane;
grant role support to user jill;

/************
Step 4: Create TAGs
************/
--create an entitlment table to demonstrate numeric values maped to actual clearance level
use role sysadmin;
create or replace table DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MAP (id numeric,level string);
insert into DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MAP 
values
(500,'TOP_SECRET'),
(400,'SECRET'),
(300,'CONFIDENTIAL'),
(100,'PUBLIC');

-- Create tag to restrict PII/CLEARANCE level
-- clearance levels 
--TOP_SECRET : 500 : access to all data
--SECRET : 400 : any object marked as SECRET or below
--CONFIDENTIAL : 300 : any object marked as CONFIDENTIAL or below
--PUBLIC: 100 : any object marked as PUBLIC only
USE ROLE TAG_ADMIN;
USE SCHEMA DEMO_DB.TAG_BASED_MASKING_DEMO;
CREATE OR REPLACE TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL ALLOWED_VALUES '500','400','300','100';
--another TAG for column type
--this is to demonstrate how we can apply multiple TAGS on a column
CREATE OR REPLACE TAG DEMO_DB.TAG_BASED_MASKING_DEMO.COLUMN_TYPE ALLOWED_VALUES 'EMAIL','FAX','PHONE';

/***************
Step 5: Create Masking Polices
****************/

-- Create Masking policies for three data types (string, number, date)
use role sysadmin; -- or role with permisison create masking policies
CREATE OR REPLACE MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_STRING AS (val string) returns string ->
CASE
    -- Since we have numeric values, we can use >= to determine access level
    WHEN SYSTEM$GET_TAG('CLEARANCE_LEVEL',current_user(),'USER') >= SYSTEM$GET_TAG_ON_CURRENT_COLUMN('CLEARANCE_LEVEL') 
        THEN VAL
    -- restrcited data but if it's email, we will show the domain part
    WHEN SYSTEM$GET_TAG_ON_CURRENT_COLUMN('COLUMN_TYPE') = 'EMAIL'
        THEN 'pii-restricted' ||SUBSTR(val, position('@', val, 1),len(val))
    ELSE '*** HIGHER CLEARANCE REQUIRED - STRING IS MASKED ***'    
END;

CREATE OR REPLACE MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_DATE AS (val date) returns date ->
CASE
    -- Since we have numeric values, we can use >= to determine access level
    WHEN SYSTEM$GET_TAG('CLEARANCE_LEVEL',current_user(),'USER') >= SYSTEM$GET_TAG_ON_CURRENT_COLUMN('CLEARANCE_LEVEL') 
        THEN VAL
    ELSE null  
END;

CREATE OR REPLACE MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_NUMBER AS (val numeric) returns numeric ->
CASE
    -- Since we have numeric values, we can use >= to determine access level
    WHEN SYSTEM$GET_TAG('CLEARANCE_LEVEL',current_user(),'USER') >= SYSTEM$GET_TAG_ON_CURRENT_COLUMN('CLEARANCE_LEVEL') 
        THEN VAL
    ELSE -99999  
END;

/**************
Step 6: Assign Masking Policies to TAG
***************/

-- Apply masking policies to tag
USE ROLE TAG_ADMIN;
ALTER TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL SET 
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_STRING,
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_DATE,
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_NUMBER;


/**********
Step 7: Create Sample Data
************/

-- Create a table for testing
USE ROLE SYSADMIN;
use warehouse demo_build_wh;
CREATE OR REPLACE TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER 
(ID NUMBER, 
NAME VARCHAR, 
DOB DATE, 
SSN VARCHAR,
DEPT VARCHAR, 
EMAIL VARCHAR);

-- Insert random data into dummy table
INSERT INTO DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER
SELECT UNIFORM(10000,99999,ABS(RANDOM())) AS ID, 
RANDSTR(abs(random()) % 10,RANDOM()) || ' ' ||  RANDSTR(10,RANDOM()) AS NAME, 
'1950-01-01'::DATE AS DOB, 
UNIFORM(111111111,999999999,ABS(RANDOM())) AS SSN, 
RANDSTR(10,RANDOM()) AS DEPT ,
RANDSTR(10,RANDOM()) || '@' || RANDSTR(5,RANDOM()) || '.' || RANDSTR(3,RANDOM()) AS EMAIL 
FROM TABLE(GENERATOR(ROWCOUNT => 50));

--let's see teh sample data
select * from DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER
limit 10;

/************
Step 8: TAG Columns
*************/

-- Apply tag to columns
use role TAG_ADMIN;
USE SCHEMA DEMO_DB.TAG_BASED_MASKING_DEMO;

ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN ID 
  SET TAG CLEARANCE_LEVEL ='300';-- CONFIDENTIAL
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN NAME 
  SET TAG CLEARANCE_LEVEL ='100';-- PUBLIC
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN DOB 
  SET TAG CLEARANCE_LEVEL ='400';-- SECRET
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN SSN 
  SET TAG CLEARANCE_LEVEL ='500';--TOP_SECRET
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN DEPT 
  SET TAG CLEARANCE_LEVEL ='100';-- PUBLIC
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN EMAIL 
  SET TAG CLEARANCE_LEVEL ='400';-- SECRET
--additional masking for EMAIL column
ALTER TABLE DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER MODIFY COLUMN EMAIL 
  SET TAG COLUMN_TYPE ='EMAIL';

/*************
Step 9: TAG USERS
**************/
-- Apply tag to users
use role TAG_ADMIN;
USE SCHEMA DEMO_DB.TAG_BASED_MASKING_DEMO;
-- lets provide clearance to users
-- we have there users JACK, JOHN and JANE
alter user JOHN SET TAG CLEARANCE_LEVEL ='500'; --TOP_SECRET

alter user JACK SET TAG CLEARANCE_LEVEL ='400'; -- SECRET

alter user JANE SET TAG CLEARANCE_LEVEL ='300'; -- CONFIDENTIAL

alter user JILL SET TAG CLEARANCE_LEVEL ='100'; -- PUBLIC  

/*****
TAG Based masking policy testing
*****/

--lets see who has what clearance level
use role sysadmin;
use warehouse DEMO_BUILD_WH;

--lets test it hard coded
select SYSTEM$GET_TAG('CLEARANCE_LEVEL','JOHN','USER');

declare
    rs_usrs        resultset;
    get_tag_val    varchar;
begin
    rs_usrs := (select value as user_nm from table (flatten(input =>array_construct('JOHN','JACK','JANE','JILL'))) ); 
    
    create or replace table res_user_tag (user_nm varchar(100), tag_val varchar(100)); 
    let cur_usrs cursor for rs_usrs;
    for rec in cur_usrs do
        get_tag_val := 'insert into res_user_tag select ''' || rec.user_nm || ''' user_nm, system$get_tag(''DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL'', ''' || rec.user_nm || ''', ''user'') tag_val';
        execute immediate :get_tag_val;
    end for;

    rs_usrs := (select * exclude ID from res_user_tag inner join DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MAP on TAG_VAL = ID);
    drop table res_user_tag;
    return table(rs_usrs);
end;


--lets see which column has what clearance level

declare
    rs_cols        resultset;
    get_tag_val    varchar;
begin
    rs_cols := (select concat('''DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER.',COLUMN_NAME,'''') as COLUMN_NAME
        from DEMO_DB.INFORMATION_SCHEMA.COLUMNS where table_name = 'CUSTOMER'); 
    create or replace table res_user_tag (COLUMN_NAME varchar(100), tag_val varchar(100)); 
    let cur_usrs cursor for rs_cols;
    for rec in cur_usrs do
        get_tag_val := 'insert into res_user_tag select ' || 
            rec.COLUMN_NAME || 
            ' COLUMN_NAME, system$get_tag(''DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL'', ' || 
            rec.COLUMN_NAME
            || ', ''COLUMN'') tag_val';
        execute immediate :get_tag_val;
    end for;

    rs_cols := (select * exclude ID from res_user_tag inner join DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MAP on TAG_VAL = ID);
    drop table res_user_tag;
    return table(rs_cols);
end;

--lets see what masking policy is applied on the columns
use role sysadmin;
SELECT policy_name,policy_kind, REF_ENTITY_NAME, REF_ENTITY_DOMAIN, REF_COLUMN_NAME,TAG_NAME
FROM TABLE (DEMO_DB.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_DOMAIN => 'TABLE',
  REF_ENTITY_NAME => 'DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER' )
);


/******
Check as user
**********/

-- login as JACK, JOHN, JANE and JILL to test who can see what data

-- irrespective of role, if user doesnt have security clearance they cant see the data.
USE ROLE ANALYST; --or whichever role is authrorized to the user
use warehouse DEMO_BUILD_WH;

--check clearance level 
select SYSTEM$GET_TAG('CLEARANCE_LEVEL',current_user(),'USER');

--check data
SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER
limit 10;

/****
Create a VIEW to check downstream testing
****/

--login as JOHN who has authrization to see data
use role sysadmin;

create view DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_VW
as
SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

grant select on DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_VW to role read_only;

-- login as JACK, JOHN, JANE and JILL to test who can see what data
SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_VW
limit 10;

-- test results, the VIEW reflects the same masking rules as the underlying table

/** 
Test cloning
*****/
use role sysadmin;
create table  DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_CLONE clone DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

-- the cloned object carries all the TAGS, and ploicy references
SELECT *
FROM TABLE (DEMO_DB.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_DOMAIN => 'TABLE',
  REF_ENTITY_NAME => 'DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_CLONE' )
);

-- login as JACK, JOHN, JANE and JILL to test who can see what data
SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_CLONE
limit 10;

-- test results, the CLONE reflects the same masking rules as the underlying table


/***
create atble as LIKE
***/
use role sysadmin;

create table  DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE like DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

SELECT *
FROM TABLE (DEMO_DB.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_DOMAIN => 'TABLE',
  REF_ENTITY_NAME => 'DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE' )
);

-- login as JACK, JOHN, JANE and JILL to test who can see what data
SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE
limit 10;


-- test results, the LIKE table is an empty table, just schema, hence no data
-- However all the masking polices are applied to the LIKE table

/****
Insert data to LIKE table
****/

--insert as an unathorized user
insert into DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE
select * from DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE
limit 10;

truncate table DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_LIKE;

-- test results when an unathrized user inserted data the new LIKE table has only masked data irrespective user
-- When data is inserted as an Authorized user data is isnerted and refelcts the masking policy.
-- in this demo scenario we only have JILL with insert permisisons, howveer JILL is not authorized to see data, hence inserted data is masked


--CTAS to a new table
-- view
create table DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_CTAS 
as
select *  from DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

SELECT *
FROM TABLE (DEMO_DB.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_DOMAIN => 'TABLE',
  REF_ENTITY_NAME => 'DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_CTAS' )
);

--Test Results: The CTAS table has no data masking policy. Howver similar to ingets only authorized user running CTAS cna ingets data
--This may break masking policies as authorized person can make a copy of the data to another table. Use RBAC to restrict CTAS from authrized users.
--the new table need masking policies applied as its a new table.


/***
Data Sharing
***/
-- use Provider studio to share data

--test results: The consumer will get an error as "User '<account locator>.<user>' does not exist or not authorized."
--The masking policy need to use INVOKER_SHARE as described in https://docs.snowflake.com/en/sql-reference/functions/invoker_share


/****
data ingestion by authorized users
*******/

-- login as JILL and insert data
INSERT INTO DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER
    SELECT UNIFORM(10000,99999,ABS(RANDOM())) AS ID, 
    RANDSTR(abs(random()) % 10,RANDOM()) || ' ' ||  RANDSTR(10,RANDOM()) AS NAME, 
    '1950-01-01'::DATE AS DOB, 
    UNIFORM(111111111,999999999,ABS(RANDOM())) AS SSN, 
    RANDSTR(10,RANDOM()) AS DEPT ,
    RANDSTR(10,RANDOM()) || '@' || RANDSTR(5,RANDOM()) || '.' || RANDSTR(3,RANDOM()) AS EMAIL 
    FROM TABLE(GENERATOR(ROWCOUNT => 50));

-- test result: JILL can insert data, data insert process doesnt effect masking policies. 
-- However even thuogh JILL can insert, when they reads data, JILL can only see masked data
-- all other authorized users will see data as per their security clearance

/****
data ingestion through tasks
*****/

-- create task to insert data
-- as long as the role/user has permisison to readwrite, we cna insert data
-- to read data we need clearance level
use role sysadmin;

CREATE or replace TASK CUSTOMER_TASK
schedule= "1 minute"
  USER_TASK_MANAGED_INITIAL_WAREHOUSE_SIZE = 'x-small'
  AS
   INSERT INTO DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER
    SELECT UNIFORM(10000,99999,ABS(RANDOM())) AS ID, 
    RANDSTR(abs(random()) % 10,RANDOM()) || ' ' ||  RANDSTR(10,RANDOM()) AS NAME, 
    '1950-01-01'::DATE AS DOB, 
    UNIFORM(111111111,999999999,ABS(RANDOM())) AS SSN, 
    RANDSTR(10,RANDOM()) AS DEPT ,
    RANDSTR(10,RANDOM()) || '@' || RANDSTR(5,RANDOM()) || '.' || RANDSTR(3,RANDOM()) AS EMAIL 
    FROM TABLE(GENERATOR(ROWCOUNT => 50));

alter task CUSTOMER_TASK resume; 

execute task CUSTOMER_TASK;


select count(1) from DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;

alter task CUSTOMER_TASK suspend; 

-- Test Result: The task can insert data into the table as sysadmin (task owner) has permisison to insert data. 
-- once data is ingested, only users with appropriate clearance can read unmasked data 

/****
DYNAMIC table
This will fail as our Masking policy is looking for current_user() and 
DYNAMIC tables are built usisng SYSTEM user
*******/
--lets create a dynamic table
create or replace dynamic table DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER_DT
TARGET_LAG = '1 minutes'
  WAREHOUSE = DEMO_BUILD_WH
  REFRESH_MODE = auto
  INITIALIZE = on_create
  AS
    SELECT * FROM DEMO_DB.TAG_BASED_MASKING_DEMO.CUSTOMER;



/******
RESET Script
********/
-- unset
USE ROLE TAG_ADMIN;
ALTER TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL UNSET 
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_STRING,
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_DATE,
MASKING POLICY DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL_MASK_NUMBER;

alter user JOHN UNSET TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL;
alter user JACK UNSET TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL;
alter user JANE UNSET TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL;
alter user JILL UNSET TAG DEMO_DB.TAG_BASED_MASKING_DEMO.CLEARANCE_LEVEL;
