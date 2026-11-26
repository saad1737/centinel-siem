#include "log_generator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * events.c - makes fake Linux log lines for testing Centinel SIEM.
 *
 * The lines look like REAL Linux logs, and ALL of them use ONE layout:
 *
 *      <Mon Day HH:MM:SS> <hostname> <program>[<pid>]: <message>
 *
 * Only the <message> part changes with the program that "wrote" it:
 *
 *   SSH / sudo / cron / firewall:
 *      Nov 26 20:38:01 centinel-srv sshd[4121]: Failed password for invalid user admin from 103.21.4.9 port 51234 ssh2
 *      Nov 26 20:38:05 centinel-srv sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
 *
 *   Web server (nginx access log forwarded through syslog, the message is the
 *   normal "combined" access log WITHOUT its own date, because the syslog
 *   header already has the time):
 *      Nov 26 20:38:01 centinel-srv nginx[812]: 103.21.4.9 - - "GET /.env HTTP/1.1" 403 512 "-" "curl/8.4.0"
 *
 * Because every line starts the same way, the follower / parser can always
 * split it into: timestamp | host | program | pid | message.
*/

/* Name of the fake machine that "writes" the logs (shows in syslog lines). */
#define HOSTNAME "centinel-srv"

/* ---------------------------------------------------------------------
 * Small random number generator: Xorshift64*
 * It is fast and good enough for fake data.
 * --------------------------------------------------------------------- */
static const uint64_t XORSHIFT_MULTIPLIER = 88172645463325252ULL;
static uint64_t rng_state = XORSHIFT_MULTIPLIER; /* current state, changes on every call */

/* Gives the next big random number. */
static uint64_t rng_next(void) {
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

/* Gives a random number from 0 to n - 1. */
static uint32_t rnd(uint32_t n) {
    return (uint32_t)((rng_next() >> 32) % n);
}

/* Picks one random item from a fixed array (the array size is found automatically). */
#define PICK(arr) ((arr)[rnd(sizeof(arr) / sizeof((arr)[0]))])

/* Random process id (PID) number, used inside "sshd[1234]". */
static unsigned rnd_pid(void) { return 1000 + rnd(60000); }

/* Random client port number, like a real computer uses (1024 - 65023). */
static unsigned rnd_port(void) { return 1024 + rnd(64000); }

/* ---------------------------------------------------------------------
 * Attacker IP pool
 * We make a small list of attacker IPs once. Later we reuse them so the
 * same attacker appears many times (this is what a brute-force looks like).
 * --------------------------------------------------------------------- */
static char (*attackers)[16];      /* list of IP strings, each max 15 chars + '\0' */
static uint32_t n_attackers;       /* how many IPs are in the list */
static uint32_t sticky_idx;        /* which attacker is "active" right now */
static uint32_t sticky_left;       /* how many more lines this attacker will make */

/* Makes one random public-looking IPv4 address and writes it into `out` (16 bytes). */
static void make_attacker_ip(char* out) {
    uint32_t first;
    /* First number is 1..223. We skip 10 and 127 because they are private/local. */
    do {
        first = 1 + rnd(223);
    } while (first == 10 || first == 127);
    snprintf(out, 16, "%u.%u.%u.%u", first, rnd(256), rnd(256), 1 + rnd(254));
}

/*
 * Starts the generator. Call it ONE time before making any events.
 *  - sets a random seed so every run gives different data
 *  - creates the attacker IP pool
 */
void events_init(const GeneratorConfig* cfg) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* Mix time and process id so two generators started together
     * do not get the same seed. */
    rng_state ^= ((uint64_t)ts.tv_nsec << 20) ^ (uint64_t)ts.tv_sec ^ ((uint64_t)getpid() << 40);

    /* Xorshift stops working if the state becomes 0, so never allow 0. */
    if (!rng_state) {
        rng_state = XORSHIFT_MULTIPLIER;
    }

    /* We need at least 1 attacker IP, so we never ask malloc for 0 bytes. */
    n_attackers = cfg->attacker_ip_pool_size ? cfg->attacker_ip_pool_size : 1;
    attackers = malloc(n_attackers * sizeof *attackers);
    if (!attackers) {
        n_attackers = 0; /* attacker_ip() below has a safe fallback for this case */
        return;
    }

    for (uint32_t i = 0; i < n_attackers; i++) {
        make_attacker_ip(attackers[i]);
    }
}

/* Frees the memory from events_init(). Safe to call more than one time. */
void events_free(void) {
    free(attackers);
    attackers = NULL;
    n_attackers = 0;
}

/*
 * Returns an attacker IP.
 * The same attacker is used for 5 to 24 calls in a row,
 * so the log shows a real "burst" from one source.
 */
static const char* attacker_ip(void) {
    if (!attackers || n_attackers == 0) {
        return "203.0.113.7"; /* safe fallback if memory was not allocated */
    }
    if (sticky_left == 0) {
        sticky_idx = rnd(n_attackers);   /* choose a new attacker */
        sticky_left = 5 + rnd(20);       /* it will repeat 5..24 times */
    }
    sticky_left--;
    return attackers[sticky_idx];
}

/* Writes a random private (office/home) IPv4 into `out`. Needs 16 bytes. */
static void benign_ip(char* out) {
    if (rnd(2)) {
        snprintf(out, 16, "192.168.1.%u", 2 + rnd(250));
    } else {
        snprintf(out, 16, "10.0.0.%u", 2 + rnd(250));
    }
}

/* ---------------------------------------------------------------------
 * Word lists (vocabulary) used to build the lines.
 * IMPORTANT: do not put commas inside these texts.
 * --------------------------------------------------------------------- */
/* Normal users of the server. */
static const char* good_users[]   = {"alice", "bob", "deploy", "ubuntu", "carol"};

/* Usernames that attackers try during SSH brute force. */
static const char* attack_users[] = {"root", "admin", "test", "oracle", "postgres",
                                     "guest", "user", "git", "pi", "ftpuser"};

/* Dangerous commands used for suspicious sudo activity. */
static const char* sudo_cmds[]    = {"/usr/bin/cat /etc/shadow", "/bin/bash", "/usr/bin/vim /etc/sudoers",
                                     "/usr/sbin/useradd -m backdoor", "/usr/bin/chmod 4755 /bin/bash",
                                     "/usr/bin/passwd root", "/bin/su -"};

/* Normal jobs that cron runs. */
static const char* cron_cmds[]    = {"(root) CMD (cd / && run-parts --report /etc/cron.hourly)",
                                     "(root) CMD (/usr/lib/php/sessionclean)",
                                     "(root) CMD (test -x /usr/sbin/anacron || run-parts /etc/cron.daily)"};

/* Normal web pages. */
static const char* good_paths[]   = {"/", "/index.html", "/about", "/api/v1/status",
                                     "/static/app.js", "/images/logo.png"};

/* Normal browsers. */
static const char* good_uas[]     = {"Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
                                     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
                                     "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) Mobile/15E148"};

/* Attack tools and scripts (including a shellshock string). */
static const char* bad_uas[]      = {"sqlmap/1.7.2#stable (https://sqlmap.org)", "Mozilla/5.00 (Nikto/2.1.6)",
                                     "curl/8.4.0", "python-requests/2.31.0",
                                     "() { :;}; /bin/bash -c 'cat /etc/passwd'"};

/* Status codes for normal web traffic (200 appears more, so it is more common). */
static const unsigned good_status[] = {200, 200, 200, 200, 304, 404};

/* One web attack: HTTP method + URL path + attack name.
 * The "label" is NOT printed in the log. It is only here so the team knows
 * what each line is meant to be. */
typedef struct { const char* method; const char* path; const char* label; } WebAttack;
static const WebAttack web_attacks[] = {
    {"GET",  "/index.php?id=1%27%20OR%20%271%27=%271",                                  "sql_injection"},
    {"GET",  "/index.php?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--", "sql_injection"},
    {"GET",  "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",                             "xss"},
    {"GET",  "/../../../../etc/passwd",                                                 "path_traversal"},
    {"GET",  "/cgi-bin/..%2f..%2f..%2fbin/sh",                                          "path_traversal"},
    {"GET",  "/admin.php?cmd=cat%20/etc/passwd",                                        "command_injection"},
    {"GET",  "/cgi-bin/test.cgi",                                                       "shellshock"},
    {"GET",  "/phpmyadmin/index.php",                                                   "web_scanner"},
    {"GET",  "/.env",                                                                   "web_scanner"},
    {"POST", "/wp-login.php",                                                           "web_login_bruteforce"},
};

/* ---------------------------------------------------------------------
 * Line writers: these two functions build the final text of one line.
 * --------------------------------------------------------------------- */

/*
 * Writes ONE syslog style line into `b`.
 *   <Mon Day HH:MM:SS> <hostname> <program>[<pid>]: <message>
 * If pid is 0 we skip "[pid]" (real "sudo" lines do not have a pid).
 * Returns how many characters were written (like snprintf).
 */
static int syslog_line(char* b, size_t cap, const char* prog, unsigned pid, const char* msg) {
    char stamp[32];
    struct tm tmv;
    time_t now = time(NULL);

    localtime_r(&now, &tmv);
    strftime(stamp, sizeof stamp, "%b %e %H:%M:%S", &tmv);

    if (pid) {
        return snprintf(b, cap, "%s %s %s[%u]: %s\n", stamp, HOSTNAME, prog, pid, msg);
    }
    return snprintf(b, cap, "%s %s %s: %s\n", stamp, HOSTNAME, prog, msg);
}

/*
 * Writes ONE web access log line. It uses the SAME syslog header as every
 * other line, so the output starts with "<time> <host> nginx[pid]:" and then
 * the access log message (combined format without the date):
 *   IP - - "METHOD path HTTP/1.1" status bytes "-" "user-agent"
 */
static int web_line(char* b, size_t cap, const char* ip, const char* method, const char* path,
                    unsigned status, unsigned bytes, const char* ua) {
    char msg[768];
    int n = snprintf(msg, sizeof msg, "%s - - \"%s %s HTTP/1.1\" %u %u \"-\" \"%s\"",
                     ip, method, path, status, bytes, ua);
    if (n < 0 || (size_t)n >= sizeof msg) {
        return 0; /* message too long: gen_event() treats 0 as "no line" */
    }
    return syslog_line(b, cap, "nginx", rnd_pid(), msg);
}

/* ---------------------------------------------------------------------
 * The four traffic types.
 * Each function writes ONE line into `b` and returns its length.
 * --------------------------------------------------------------------- */

/* 1) Normal activity: good SSH login, cron job, or a normal web request. */
static int gen_benign(char* b, size_t cap, const GeneratorConfig* cfg) {
    char ip[16], msg[256];
    (void)cfg;
    benign_ip(ip);

    switch (rnd(5)) {
    case 0: /* a real user logs in with an SSH key */
        snprintf(msg, sizeof msg, "Accepted publickey for %s from %s port %u ssh2",
                 PICK(good_users), ip, rnd_port());
        return syslog_line(b, cap, "sshd", rnd_pid(), msg);

    case 1: /* a normal scheduled job */
        return syslog_line(b, cap, "CRON", rnd_pid(), PICK(cron_cmds));

    default: { /* a normal visitor opens a page */
        unsigned status = PICK(good_status);
        return web_line(b, cap, ip, "GET", PICK(good_paths), status,
                        status == 304 ? 0 : 200 + rnd(40000), PICK(good_uas));
    }
    }
}

/* 2) SSH brute force: one attacker tries many wrong logins or gets blocked. */
static int gen_ssh_bf(char* b, size_t cap, const GeneratorConfig* cfg) {
    char msg[320];
    const char* ip   = attacker_ip();      /* same attacker repeats many times */
    const char* user = PICK(attack_users);

    switch (rnd(4)) {
    case 0: /* wrong password (most common line in a real auth.log) */
        if (strcmp(user, "root") == 0) {
            snprintf(msg, sizeof msg, "Failed password for root from %s port %u ssh2", ip, rnd_port());
        } else {
            snprintf(msg, sizeof msg, "Failed password for invalid user %s from %s port %u ssh2",
                     user, ip, rnd_port());
        }
        return syslog_line(b, cap, "sshd", rnd_pid(), msg);

    case 1: /* the user name does not exist on the server */
        while (strcmp(user, "root") == 0) user = PICK(attack_users);
        snprintf(msg, sizeof msg, "Invalid user %s from %s port %u", user, ip, rnd_port());
        return syslog_line(b, cap, "sshd", rnd_pid(), msg);

    case 2: /* attacker disconnects before finishing login */
        snprintf(msg, sizeof msg, "Connection closed by %s %s %s port %u [preauth]",
                 strcmp(user, "root") == 0 ? "authenticating user" : "invalid user",
                 user, ip, rnd_port());
        return syslog_line(b, cap, "sshd", rnd_pid(), msg);

    default: /* the firewall blocks the connection to SSH port 22 */
        snprintf(msg, sizeof msg,
                 "[UFW BLOCK] IN=eth0 OUT= SRC=%s DST=%s LEN=60 TTL=52 ID=%u DF PROTO=TCP SPT=%u DPT=22 SYN",
                 ip, cfg->victim_ip, rnd(65535), rnd_port());
        return syslog_line(b, cap, "kernel", 0, msg);
    }
}

/* 3) Web attack: SQL injection, XSS, path traversal, scanners and more. */
static int gen_web_attack(char* b, size_t cap, const GeneratorConfig* cfg) {
    const WebAttack* w = &web_attacks[rnd(sizeof web_attacks / sizeof web_attacks[0])];
    unsigned status = (rnd(10) < 6) ? 403 : 200; /* 60% blocked (403) and 40% passed (200) */
    (void)cfg;

    return web_line(b, cap, attacker_ip(), w->method, w->path, status,
                    150 + rnd(1350), PICK(bad_uas));
}

/* 4) Suspicious sudo: a user runs a risky command or tries and fails. */
static int gen_sudo_abuse(char* b, size_t cap, const GeneratorConfig* cfg) {
    char msg[384];
    const char* user = PICK(good_users);
    const char* cmd  = PICK(sudo_cmds);
    (void)cfg;

    switch (rnd(3)) {
    case 0: /* sudo worked: the user ran a dangerous command as root */
        snprintf(msg, sizeof msg, "%s : TTY=pts/%u ; PWD=/home/%s ; USER=root ; COMMAND=%s",
                 user, rnd(4), user, cmd);
        break;
    case 1: /* sudo refused: this user is not allowed to use sudo */
        snprintf(msg, sizeof msg,
                 "%s : user NOT in sudoers ; TTY=pts/%u ; PWD=/home/%s ; USER=root ; COMMAND=%s",
                 user, rnd(4), user, cmd);
        break;
    default: /* sudo refused: wrong password typed 3 times */
        snprintf(msg, sizeof msg,
                 "%s : 3 incorrect password attempts ; TTY=pts/%u ; PWD=/home/%s ; USER=root ; COMMAND=%s",
                 user, rnd(4), user, cmd);
        break;
    }
    return syslog_line(b, cap, "sudo", 0, msg); /* sudo lines have no [pid] */
}

/* ---------------------------------------------------------------------
 * Main entry: choose a traffic type by the percentage ratios and make one line.
 * Example: benign 80, ssh 10, web 7, sudo 3 means 80% of lines are normal.
 * Writes ONE full line (with '\n') into `buf`.
 * Returns the number of bytes written, or 0 on error (for example buffer too small).
 * --------------------------------------------------------------------- */
size_t gen_event(char* buf, size_t cap, const GeneratorConfig* cfg) {
    int r = (int)rnd(100), n;   /* r is a random number from 0 to 99 */

    if      (r < cfg->ratio_benign)
        n = gen_benign(buf, cap, cfg);
    else if (r < cfg->ratio_benign + cfg->ratio_ssh_bf)
        n = gen_ssh_bf(buf, cap, cfg);
    else if (r < cfg->ratio_benign + cfg->ratio_ssh_bf + cfg->ratio_web_attack)
        n = gen_web_attack(buf, cap, cfg);
    else
        n = gen_sudo_abuse(buf, cap, cfg);

    /* n must be positive and must fit inside the buffer (with the final '\0'). */
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}