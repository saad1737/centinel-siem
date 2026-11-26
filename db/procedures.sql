

-- P5 logins, failed logins, logouts logs to user_history

create or replace procedure sp_record_user_access(
  p_user_id   bigint,
  p_ip        inet,
  p_action    text   -- login, failed login or logout
)
language plpgsql
security definer
set search_path = centinel, public, pg_catalog
as $$
begin
  if p_action is null or btrim(p_action) = '' then
    raise exception 'access action cannot be empty';
  end if;

  -- make sure the user actually exists before writing history
  if not exists (
        select 1 from users where user_id = p_user_id
    ) then
        raise exception 'user % does not exist', p_user_id;
  end if;
  
  insert into user_history (ip, action, user_id, created_at)
  values (p_ip, btrim(p_action), p_user_id, clock_timestamp());
end;
$$;

