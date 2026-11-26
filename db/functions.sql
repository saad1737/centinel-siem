-- this file contains the functions of the sentinel siem

--fn_is_valid_ip : this function checks if the ip is valid or not. return true if valid, else false
--takes ip as text and later on converts into ipnet because every ip  must be ipnet format
create or replace function fn_is_valid_ip(p_ip text)
returns boolean
language plpgsql
immutable       --we dont want this function to modify the db
as $$
declare
    v_ip inet;
begin
    if p_ip is null or p_ip = '' then       --we dont want ip as null
        return false;
    end if;

    if p_ip <> btrim(p_ip) then             --checks if there are any spaces around the ip or not, if there are, it is invalid
        return false;                       --if there are spaces around the ip then there is a possibility there would be multiple instances of the same ip in the db
    end if;

    if position('/' in p_ip)>0 then         --we only want ip, not range. for example if the ip is 10.0.0.0/8, it will not be valid because it is a range
        return false;
    end if;

    v_ip := p_ip::inet;                     --converting p_ip text into inet
    return true;
end;
$$;


--fn_rule_matches : this fucntion checks whether a log line matches a certain rule or not. return true if mathces, else false
--takes correlation_rule row and then matches with the log line that  was provided
create or replace function fn_rule_matches(p_rule       correlation_rule,      --takes one row from the correlation_rule table
                                           p_service    text,                  --service name from the log line
                                           p_raw        text                   --raw log
                                           )
returns boolean
language plpgsql
immutable       --we dont want this function to modify the db
as $$
begin
    select coalesce(
        p_rule.is_enabled                               --the rule must be enabled first, disabled rule doesnt match anything
        and(p_rule.service_name_match is null           --??A rule with an empty service matches any service. Otherwise the service must be the same
            or p_rule.service_name_match = ''
            or p_rule.service_name_match = p_service)
        and case p_rule.match_type                                           --looks for rules pattern inside log line
            when 'substring' then position (p_rule.match_pattern in p_raw)>0 --it returns where the rule first matches
            when 'regex' then p_raw ~ p_rule.match_pattern                   --regex used for postgresql pattern matching
            else false                                                       --unknown match type
        end,
    false);     --if there is null then it means no match
$$;


--fn_get_ban_list : returns the ips which must be banned now
--returns ips whose latest ledger now says ban
create or replace function fn_get_ban_list()
returns table (ban_ip_net)
language plpgsql
stable
as $$
    select latest.target_ip
    from (
        select distinct on (l.target_ip)    --keeps only the first row for each different target ip
        l.target_ip, l.decision
        from soar_remediation_ledger as l
        order by l.target_ip, l.created_at DESC, l.ledger_id DESC
    ) as latest
    where latest.decision = 'ban';
$$;


--fn_get_alert_context : returns the information regarding an attack to the man or the llm to summerize