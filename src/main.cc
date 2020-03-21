//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ble_beacon.h"
#include "filters.h"
#include "gateway.h"
#include "logger.h"

// globals
unsigned int g_verbose = 0;
const char* g_version = "0.1";

// signal handler
static void quit (int);

static void synopsis (const char*, const char*, const char*);

int
main (int argc, char** argv)
{
    // bluetooth device
    const char *dev = nullptr;
    // lescan options (as in hcitool)
    uint16_t lescan_interval = 0x0f;
    uint8_t lescan_own_type = 0;	// 0:public, 1:random
    uint8_t lescan_scan_type = 0;	// 0:passive, 1:active
    uint8_t lescan_filter_policy = 0;	// 0:none, 1:whitelist (created by "hcitool lewladd ...")
    uint8_t lescan_filter_type = 0;	// 'g': general, 'l':limited
    uint8_t lescan_filter_dup = 0;	// 0:allow dup, 1:discard dup -- for SET_SCAN_ENABLE (enable, filter_dup)

    // MQTT
    char* mqtt_host = getenv ("MQTT_SERVER");
    mqtt_host = mqtt_host ? mqtt_host : strdup ("localhost");
    unsigned int mqtt_port = 1883;
    const char* mqtt_topic = "beacon";
    // filters
    std::list<const char*> whitelist;
    std::list<const char*> beacon_types;
    unsigned int cutoff_duration = 0;
    // JSON formatting
    bool generic_beacon = false;
    // watchdog
    bool watchdog_enabled = false;
    // process info
    const char *program = basename (argv[0]);
    char machine[100];
    gethostname (machine, 100);

    // command-line args
    for (int i = 1; i < argc; i++)
    {
        // SCANNER options
        if (!strcmp (argv[i], "-i"))
            dev = argv[++i];
        else if (!strncmp (argv[i], "--interval=", 11))
            lescan_interval = atoi (argv[i] + 11);
        //else if (!strcmp (argv[i], "--active"))
        //    lescan_scan_type = 1;
        else if (!strcmp (argv[i], "--privacy"))
            lescan_own_type = 1;
        //else if (!strncmp (argv[i], "--discovery=", 12))
        //{
        //    char ch = argv[i][12];
        //    if (ch == 'l' || ch == 'g') lescan_filter_type = ch;
        // }

        // TRANSMITTER options
        else if (!strncmp (argv[i], "--wl=", 5))
        {
            //lescan_filter_policy = 1;
            for (char* tok = strtok (argv[i] + 12, ","); tok; tok = strtok (NULL, ","))
                whitelist.push_back (strdup (tok));
        }
        else if (!strncmp (argv[i], "--beacon=", 9))
        {
            for (char* tok = strtok (argv[i] + 9, ","); tok; tok = strtok (NULL, ","))
                beacon_types.push_back (strdup (tok));
        }
        else if (!strncmp (argv[i], "--dup", 5))
        {
            lescan_filter_dup = 0;
            cutoff_duration = 0;
        }
        else if (!strncmp (argv[i], "--no-dup", 8))
        {
            //lescan_filter_dup = 1;
            char* str = strchr (argv[i], '=');
            if (str && isdigit (str[1]))
                cutoff_duration = atoi (str + 1);
            else
                cutoff_duration = 10;	// 10s
        }
        // MQTT-related
        else if (!strcmp (argv[i], "-b"))
            mqtt_host = argv[++i];
        else if (!strcmp (argv[i], "-t"))
            mqtt_topic = argv[++i];
        // JSON formatting
        else if (!strcmp (argv[i], "--generic"))
            generic_beacon = true;
        // watchdog
        else if (!strcmp (argv[i], "--watchdog"))
            watchdog_enabled = true;

        // miscellaneous
        else if (!strcmp (argv[i], "-v"))
            g_verbose = 1;
        else if (!strncmp (argv[i], "--verbose=", 10))
            g_verbose = atoi (argv[i] + 10);
        else if (!strcmp (argv[i], "-V") || !strcmp (argv[i], "--version"))
        {
            printf ("%s\n", g_version);
            exit (0);
        }
        else if (!strcmp (argv[i], "-h"))
        {
            synopsis (program, g_version, mqtt_topic);
            exit (0);
        }
        else
        {
            fprintf (stderr, "** unknown option: \"%s\"\n", argv[i]);
            assert (false);
        }
    }

    // validation: whitelist
    for (auto bdaddr : whitelist)
        if (strlen (bdaddr) != 17)
        {
            fprintf (stderr, "invalid bdaddr specification: %s\n", bdaddr);
            exit (-1);
        }

    // validation: beacon_types
    const char* supported_formats[] = {"ibeacon", NULL};
    for (auto fmt : beacon_types)
    {
        bool found = false;
        for (int i = 0; supported_formats[i]; i++)
        {
            if (!strcmp (supported_formats[i], fmt))
            {
                found = true;
                break;
            }
        }
        if (!found)
        {
            fprintf (stderr, "invalid format specification: %s\n", fmt);
            exit (-1);
        }
    }

    // mqtt
    char* mqtt_ptr = strchr (mqtt_host, ':');
    if (mqtt_ptr)
    {
        *mqtt_ptr = '\0';
        mqtt_port = atoi (mqtt_ptr + 1);
    }

    // traps
    signal (SIGTERM, quit);
    signal (SIGHUP, quit);
    signal (SIGINT, quit);

#if 1
    // daemonization
    pid_t child_pid = fork ();
    if (child_pid < 0) { fprintf (stderr, "fork failed\n"); exit (1); }
    if (child_pid > 0) { fprintf (stderr, "forked: %d\n", child_pid); exit (0); }
    umask (0);
    pid_t sid = setsid ();  // run the process in a new session
    if (sid < 0) exit(1);
    chdir ("/");
    close (STDIN_FILENO);
    close (STDOUT_FILENO);
    close (STDERR_FILENO);
#endif

    openlog (program, LOG_PID, LOG_USER);

    // scanner params
    gateway::scanner_params s_params;
    s_params.device = dev;
    s_params.lescan_interval = 0x0f;
    s_params.lescan_own_type = 0;	// 0:public, 1:random
    s_params.lescan_scan_type = 0;	// 0:passive, 1:active
    s_params.lescan_filter_policy = 0;	// 0:none, 1:whitelist (created by "hcitool lewladd ...")
    s_params.lescan_filter_type = 0;	// 'g': general, 'l':limited
    s_params.lescan_filter_dup = 0;	// 0:allow dup, 1:discard dup -- for SET_SCAN_ENABLE (enable, filter_dup)

    // notifier params
    gateway::notifier_params n_params;
    n_params.mqtt_host = mqtt_host;
    n_params.mqtt_port = mqtt_port;
    n_params.mqtt_topic = mqtt_topic;

    n_params.whitelist = &whitelist;
    n_params.beacon_types = &beacon_types;
    n_params.cutoff_duration = cutoff_duration;

    n_params.json_generic = generic_beacon;
    n_params.watchdog_enabled = watchdog_enabled;

    n_params.program = program;
    n_params.machine = machine;
    n_params.pid = getpid ();

    gateway::setup (&s_params, &n_params);
    gateway::start ();  // non-blocking

    while (1) sleep (3600);

    return (0);
}

// signal handler
static void
quit (int sig)
{
    syslog (LOG_NOTICE, "quit (signal = %d)", sig);

    gateway::terminate ();

    closelog ();

    exit (0);
}

// wrapper of the common syslog function
void
_syslog (int prio, const char* fmt, ...)
{
    if (g_verbose == 0 && prio >= LOG_NOTICE) return;
    if (g_verbose == 1 && prio >= LOG_INFO) return;
    if (g_verbose == 2 && prio >= LOG_DEBUG) return;
        
    va_list ap;
    va_start (ap, fmt);
    vsyslog (prio, fmt, ap);
    va_end (ap);
}

static void
synopsis (const char* prog, const char* ver, const char* topic)
{
    printf ("%s v%s -- scan BLE beacons and transmit them in JSON over MQTT\n", prog, ver);
    printf ("usage: %s <option>*\n", prog);
    printf ("options:\n\n");

    printf ("  [scanner options]\n");
    printf ("  -i <dev>\t\tscan beacons through <dev>\n");
    printf ("  --interval=<dt>\tset scan interval to <dt>\n");
    printf ("  --privacy\t\tset own_baddr_type to random\n");
    printf ("\n");

    printf ("  [transmitter options]\n");
    printf ("  -b <mqtt_broker>\tspecify mqtt broker (default: localhost:1883)\n");
    printf ("  -t <mqtt_topic>\tspecify mqtt topic (default: %s)\n", topic);
    printf ("  --wl=<a>,<a>,..\tspecify bluetooth device addresses for filtering\n");
    printf ("  --beacon=<b>,<b>,..\tspecify beacon types for filtering (ex: ibeacon)\n");
    printf ("  --dup\t\t\ttransmit duplicate beacons\n");
    printf ("  --no-dup[=<dt>]\tignore duplicate beacons (during any <dt>-sec period)\n");
    printf ("  --generic\t\tformat beacons in JSON w/o considering their types\n");
    printf ("  --watchdog\t\trespond to \"ping\" from watchdog with \"pong\"\n");
    printf ("\n");

    printf ("  --verbose=<level>\tset verbosity level (0-3)\n");
    printf ("  -v, --verbose\t\tsynonymous with \"--verbose=1\"\n");
    printf ("  -V, --version\t\tdisplay version information\n");
    printf ("  -h, --help\t\tdisplay this help\n");
    printf ("\n");

}
