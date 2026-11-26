create schema if not exists centinel;

--1. MITER ATT&CK TABLE

create table if not exists mitre_attack(
    mitre_id bigserial primary key,         -- BIGSERIAL type is big int but increments everytime new item is inserted in table, mitre id is the uniqe identifier we are arbitrarily assigning.
    technique_id text not null unique,      --the id provided by MITRE for a "technique" (and also subtechniques, which we append with a '.')
    technique_name text not null,           --name *might* not be unique cause some names might be too common and used elsewhere
    tactic_name text not null               --the umbrella tactic or work , like "stealth" or "priviledge escalation"
);

--2. Correlation Rules TABLE
create table if not exists correlation_rules(
    rule_id bigserial primary key,
    rule_name text not null unique,         --provided by us (i think?)
    service_name_match text,                --intentionally NULL is valid, such that null would mean any service match
    match_type text not null check (match_type IN ('substring','regex')), --either raw string match, or a regular expression
    match_pattern text not null,
    severity smallint not null check (severity between 1 AND 4),    --smallint and not text to save storage
    windows_seconds int not null check (windows_seconds > 0),
    threshold_count int not null check (threshold_count > 0),       --both cannot be 0 because its used in the "leaky bucket" (?) formula to divide
    response_action text not null check (response_action IN ('alert_only','ban_ip')),
    mitre_id bigint references mitre_attack(mitre_id),
    is_enabled boolean not null default true
);

--3. Detection Bucket TABLE
--composite primary key, rule id and source ip together as PK
create table if not exists detection_bucket(
    rule_id bigint not null references correlation_rules(rule_id),
    source_ip inet not null,
    current_fill numeric not null default 0,
    last_event_at timestamptz not null default clock_timestamp(),

    primary key (rule_id,source_ip)
);

--4. Suspicious Logs TABLE
--we partion it by time because deleting a table or two by time is a much resource efficient operation than searching whole table and deleting individual rows. 
--partion creates multiple "child tables", which can be easily dealt with
create table if not exists suspicious_logs(
    log_id bigserial,
    event_time timestamptz not null,
    ingestion_time timestamptz not null,    --even time is when the log has occured on the machine, timestamped by the VPS, the ingestion time is given once per batch to all logs ingested in that time.
    source_ip inet not null,
    service_name text not null,
    raw_log text not null check (octet_length(raw_log) <= 2048),    --inserting a 2KB storage cap, the octet_length function gets the byte value.
    source_file text not null,
    
    primary key (event_time, log_id)        --such that each partitioned table can be seperately identified
) partition by range (event_time);

--5.Security Alerts
create table if not exists security_alerts(
    alert_id bigserial primary key,
    rule_id big int references correlation_rules(rule_id),
    source_ip inet not null,
    created_at timestamptz not null default clock_timestamp(),
    alert_status text not null default 'open' check (alert_status IN ('open' , 'investigating', 'resolved', 'false_positive')),
);

--5.5 
create uniqe index if not exists idx_unique_active_alert 
on security_alerts (rule_id,source_ip)
where alert_status in ('open', 'investigating');
--we do not put unique clause inside the table because we want the uniqueness to be only on alerts which will be/are being worked on.
--otherwise a closed alert, with same combination of id and ip, would not let a new alert be created.

--6. SOAR remidiation TABLE
create table if not exists soar_remidiation_ledger(
    ledger_id bigserial primary key,
    target_ip inet not null,
    alert_id bigint references security_alerts(alert_id),
    decision text not null check (decision IN ('ban','unban')),
    created_at timestamptz not null default clock_timestamp()
);

--7. users TABLE
create table if not exists users(
    user_id bigserial primary_key,
    username text not null unique,
    password_hash text not null,
    role text not null check (role IN ('admin', 'analyst')),
    is_active boolean not null default true
);

--8. User History TABLE

create table if not exists user_history(
    history_id bigserial primary key,
    ip inet not null,
    action text not null,
    user_id bigint not null references users(user_id),
    created_at timestamptz not null default clock_timestamp()
);
