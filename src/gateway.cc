//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <functional>
#include <list>
#include <mutex>
#include <thread>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <mosquitto.h>
#include <nlohmann/json.hpp>
#include <uuid/uuid.h>

#include "ble_beacon.h"
#include "filters.h"
#include "gateway.h"
#include "logger.h"

using json = nlohmann::json;
using namespace gateway;

std::thread *g_scanner = nullptr;
std::thread *g_notifier = nullptr;

enum state_t {S_INIT=0, S_READY, S_RUNNING, S_STOPPED};
state_t g_scanner_state;
state_t g_notifier_state;

// shared variables
std::list<le_advertising_info*> g_beacons, g_beacon_pool;
std::mutex g_mutex;
  // for mutual exclusion b.w. scanner (on_advertise) and notifier (notify_of_beacons)

// scanner
static void scanner_setup (const scanner_params*);
static void scanner_start ();
static void scanner_stop ();
static void scanner_terminate ();

// notifier
static void notifier_setup (const notifier_params*);
static void notifier_start ();
static void notifier_stop ();
static void notifier_terminate ();

//
void
gateway::setup (const scanner_params *s_params, const notifier_params *n_params)
{
    scanner_setup (s_params);
    notifier_setup (n_params);
}

void
gateway::start ()
{
    notifier_start ();
    scanner_start ();
}

void
gateway::stop ()
{
    scanner_stop ();
    notifier_stop ();
}

void
gateway::terminate ()
{
    scanner_terminate ();
    notifier_terminate ();
}

// -------
// SCANNER
// -------

int g_socket = 0;
uint8_t g_lescan_filter_dup;
  // for SET_SCAN_ENABLE (enable, filter_dup)

static void scan_beacons ();
static void on_advertise (le_advertising_info* info);

static void
scanner_setup (const scanner_params *params)
{
    syslog (LOG_DEBUG, "scanner_setup");

    if (g_scanner_state != S_INIT) return;

    const char *device = params->device;
    bdaddr_t *bdaddr = params->bdaddr;
    if (!bdaddr && device && !strncmp (device, "hci", 3))
    {
        bdaddr = (bdaddr_t*) malloc (sizeof (bdaddr_t));
        int dev_id = atoi (device + 3);
        hci_devba (dev_id, bdaddr);
        syslog (LOG_NOTICE, "device \"%s\" -> baddr %s", params->device, batostr (bdaddr));
    }
    int dev_id;
    int rslt = ble_open_device (bdaddr, &dev_id, &g_socket);
    if (rslt != 0) { syslog (LOG_ERR, "ble_open_device failed: %d", rslt); raise (SIGTERM); }

    // LE_SET_SCAN_PARAMETERS (0x000B)
    le_set_scan_parameters_cp lescan_params;
    lescan_params.type = params->lescan_scan_type;		// 0:passive, 1:public
    lescan_params.interval = htobs (params->lescan_interval);	//
    lescan_params.window = htobs (params->lescan_interval);	//
    lescan_params.own_bdaddr_type = params->lescan_own_type;	// 0:public, 1:random
    lescan_params.filter = params->lescan_filter_policy;	// 0:accept_any, 1:whitelist

    rslt = ble_set_scan_params (g_socket, &lescan_params);
    if (rslt != 0)
    {
        syslog (LOG_ERR, "ble_set_scan_params failed: (%d) %s", errno, strerror (errno));
        raise (SIGTERM);
    }

    g_lescan_filter_dup = params->lescan_filter_dup;

    g_scanner_state = S_READY;

}

static void
scanner_start ()
{
    syslog (LOG_DEBUG, "scanner_start");

    if (g_scanner_state != S_READY) return;

    // LE_SET_SCAN_ENABLE (0x000C)
    int rslt = ble_set_scan_enable (g_socket, true, g_lescan_filter_dup);
    if (rslt != 0)
    {
        syslog (LOG_ERR, "ble_set_scan_enable failed: (%d) %s", errno, strerror (errno));
        raise (SIGTERM);
    }

    // scanner
    // store advertising beacons into g_beacons
    g_scanner = new std::thread (scan_beacons);

    g_scanner_state = S_RUNNING;
}

static void
scanner_stop ()
{
    syslog (LOG_DEBUG, "scanner_stop");

    switch (g_scanner_state)
    {
    case S_INIT:
        return;
    case S_READY:
        break;
    case S_RUNNING:
        g_scanner_state = S_STOPPED;
        break;
    case S_STOPPED:
        break;
    }

    // assert: g_scanner_state == S_READY or S_STOPPED
}

static void
scanner_terminate ()
{
    syslog (LOG_DEBUG, "scanner_terminate");

    switch (g_scanner_state)
    {
    case S_INIT:
        return;
    case S_READY:
        break;
    case S_RUNNING:
        scanner_stop ();
        break;
    case S_STOPPED:
        break;
    }

    // assert: g_scanner_state == S_READY or S_STOPPED

    // ble
    ble_close_device (g_socket);

    g_scanner_state = S_INIT;
}

//
static void
scan_beacons ()
{
    //syslog (LOG_NOTICE, "start scanning: #filter=%d cache(%ds) broker=%s:%d topic=\"%s\" verbosity=%d",
    //        g_filters.size(), g_cache_duration, mqtt_host, mqtt_port, g_mqtt_topic, g_verbose);

    // blocking -- no way of stopping it.
    int rslt = ble_scan_advertising_devices (g_socket, 0, on_advertise);
    if (rslt != 0)
    {
        syslog (LOG_ERR, "ble_scan_advertising_devices: (%d) %s", errno, strerror (errno));
    }
}

// callback for ble_scan_advertising_devices
//
// - on_advertise just puts each scanned beacon into an internal queue and returns
// - notify_of_beacons (running in parallel) does the real job
//
static void
on_advertise (le_advertising_info* info)
{
    if (!info) return;

    g_mutex.lock ();

    le_advertising_info* copy;
    if (g_beacon_pool.empty ())
        copy = (le_advertising_info*) malloc (sizeof (le_advertising_info) + 30);
    else
    {
        copy = g_beacon_pool.front ();
        g_beacon_pool.pop_front ();
    }

    memcpy (copy, info, sizeof (le_advertising_info));
    memcpy (copy->data, info->data, info->length);
    g_beacons.push_back (copy);

    g_mutex.unlock ();
}

// --------
// NOTIFIER
// --------

std::list<std::function<le_advertising_info* (le_advertising_info*)>> g_filters;

mosquitto *g_mosq = nullptr;
const char *g_mqtt_topic = "beacon";
//std::list<mosquitto_message*> g_mqtt_messages;
bool g_json_generic = false;
  // awareness with beacon types such as ibeacon, eddystone, etc.
bool g_watchdog_enabled = false;

// process info
const char *g_program = nullptr;
const char *g_machine = nullptr;
pid_t g_pid = 0;

static void notify_of_beacons ();
static void notify (le_advertising_info *info);
static void jsonify_generic (const le_advertising_info*, json*);
static void jsonify_ibeacon (const le_advertising_info*, json*);

// mqtt callbacks
// notifier recognizes "watchdog/ping" messages from watchpup, and responds with "watchdog/pong"
static void mosq_on_message (mosquitto*, void *user, const mosquitto_message *msg);
// attempt of reconnection.
static void mosq_on_disconnect (mosquitto*, void *user, int reason);

//
void
notifier_setup (const notifier_params *params)
{
    syslog (LOG_DEBUG, "notifier_setup");

    if (g_notifier_state != S_INIT) return;

    // mqtt
    mosquitto_lib_init ();
    g_mosq = mosquitto_new (NULL, true, NULL);
      // id, clean_session, user_data
    if (!g_mosq)
    {
        syslog (LOG_ERR, "mosquitto_new failed: (%d) %s (%d)", errno, mosquitto_strerror(errno));
        raise (SIGTERM);
    }

    mosquitto_message_callback_set (g_mosq, mosq_on_message);
    mosquitto_disconnect_callback_set (g_mosq, mosq_on_disconnect);

    const int keep_alive = 60;
      // the number of seconds after which the broker should send a PING message to the client
      // note: connection will be lost if no message is transmitted for (1.5 * keep_alive) seconds
    int rslt = mosquitto_connect_bind (g_mosq, params->mqtt_host, params->mqtt_port, keep_alive, NULL);
      // mosq, host, port, keep_alive, bind_addr
    if (rslt != MOSQ_ERR_SUCCESS)
    {
        syslog (LOG_ERR, "mosquitto_connect_bind failed (%s): (%d) %s",
                params->mqtt_host, rslt, mosquitto_strerror (rslt));
        raise (SIGTERM);
    }

    // for publishing beacons
    g_mqtt_topic = params->mqtt_topic;

    // for responding to calls from watchdog
    g_watchdog_enabled = params->watchdog_enabled;
    if (g_watchdog_enabled)
        mosquitto_subscribe (g_mosq, NULL, "watchdog/ping", 0);
        // mosq, msg_id, topic, qos

    // filters -- helpers for notifier
    g_filters.clear ();
    std::list<const char*> *wl = params->whitelist;
    std::list<const char*> *btypes = params->beacon_types;
    unsigned duration = params->cutoff_duration;
    if (!wl->empty())
    {
        auto f = [=](le_advertising_info* info) { return (filter_by_senders(info, wl)); };
        g_filters.push_back (f);
    }
    if (!btypes->empty())
    {
        auto f = [=](le_advertising_info* info) { return (filter_by_formats(info, btypes)); };
        g_filters.push_back (f);
    }
    if (duration > 0)
    {
        auto f = [=](le_advertising_info* info) { return (drop_if_duplicate(info, duration)); };
        g_filters.push_back (f);
    }

    // json formatting
    g_json_generic = params->json_generic;

    // process info
    g_program = params->program;
    g_machine = params->machine;
    g_pid = params->pid;

    g_notifier_state = S_READY;
}

static void
notifier_start ()
{
    syslog (LOG_DEBUG, "notifier_start");

    if (g_notifier_state != S_READY) return;

    // mqtt (for notifier)
    // [note]
    // even if this is a no-subscribe-but-publish-only program,
    // it is still necessary to invoke mosquitto_loop_start
    // for responding to calls from the broker (such as PING messages, for instance)
    int rslt = mosquitto_loop_start (g_mosq);	// threaded

    // notifier
    g_notifier = new std::thread (notify_of_beacons);

    g_notifier_state = S_RUNNING;
}

static void
notifier_stop ()
{
    syslog (LOG_DEBUG, "notifier_stop");

    switch (g_notifier_state)
    {
    case S_INIT:
        return;
    case S_READY:
        break;
    case S_RUNNING:
        g_notifier_state = S_STOPPED;
        g_notifier->join ();
        break;
    case S_STOPPED:
        break;
    }

    // assert: g_notifier_state == S_READY or S_STOPPED

}

static void
notifier_terminate ()
{
    syslog (LOG_DEBUG, "notifier_terminate");

    switch (g_notifier_state)
    {
    case S_INIT:
        return;
    case S_READY:
        break;
    case S_RUNNING:
        notifier_stop ();
        break;
    case S_STOPPED:
        break;
    }

    // assert: g_notifier_state == S_READY or S_STOPPED

    // mqtt
    if (g_mosq)
    {
        mosquitto_disconnect (g_mosq);
        //mosquitto_loop_stop (g_mosq, false);
        mosquitto_destroy (g_mosq);
        mosquitto_lib_cleanup ();
        g_mosq = nullptr;
    }

    g_notifier_state = S_INIT;
}

// nofity, via MQTT, of those advertising beacons collected by on_advertise.
//
// - it extracts beacons from an internal queue and transmits them via MQTT
// - it is BLOCKING while g_running is true, and is supposed to be threaded.
//
static void
notify_of_beacons ()
{
    while (g_notifier_state == S_RUNNING)
    {
        if (g_beacons.empty ())
        {
            std::this_thread::sleep_for (std::chrono::milliseconds (100));
            continue;
        }

        g_mutex.lock ();
        le_advertising_info* info = g_beacons.front ();
        g_beacons.pop_front ();
        g_mutex.unlock ();

        notify (info);

        g_mutex.lock ();
        g_beacon_pool.push_back (info);
        g_mutex.unlock ();
    }
}

// single beacon notifier
static void
notify (le_advertising_info *info)
{
    if (!info) return;

    // typedef struct
    // {
    //     uint8_t         evt_type;
    //     uint8_t         bdaddr_type;
    //     bdaddr_t        bdaddr;
    //     uint8_t         length;
    //     uint8_t         data[0];
    // } __attribute__ ((packed)) le_advertising_info;

    char bdaddr[18];
    ba2str (&info->bdaddr, bdaddr);
    syslog (LOG_INFO,
            "evt_type=%d bdaddr_type=%d bdaddr=%s length=%d\n",
            info->evt_type, info->bdaddr_type, bdaddr, info->length);

    if (info->length > 31)
    {
        syslog (LOG_ERR, "length = %d > 31 (discarded)", info->length);
        return;
    }

    // filtering
    // each filter decides if info should be processed or not.
    le_advertising_info* filtered = info;
    for (auto f : g_filters)
    {
        filtered = f (filtered);
        if (!filtered)
        {
            syslog (LOG_DEBUG, "filtered out");
            return;
        }
    }

    char* info_str = (char*) malloc (info->length * 3 + 1);
    for (int i = 0; i < info->length; i++)
        sprintf (info_str + 3 * i, "%02x ", info->data[i]);
    info_str[info->length * 3 - 1] = '\0';
    syslog (LOG_NOTICE, "[%s] %s", bdaddr, info_str);

    // jsonification
    json obj;
    if (ble_check_advertising_data_ibeacon (info))
        jsonify_ibeacon (info, &obj);
    else
        jsonify_generic (info, &obj);

    // mqtt publish
    std::string str = obj.dump ();
    //syslog (LOG_NOTICE, str.c_str ());
    for (int k = 0;; k++)
    {
        int rslt = mosquitto_publish (g_mosq, NULL, g_mqtt_topic, str.length() + 1, str.c_str(), 0, false);
          // mosq, msg_id, topic, len, payload, qos, retain
        if (rslt == MOSQ_ERR_SUCCESS) break;

        syslog (LOG_ERR, "mosquitto_publish failed: (%d) %s / %s", rslt, mosquitto_strerror (rslt), strerror (errno));
        rslt = mosquitto_reconnect (g_mosq);
        if (rslt == MOSQ_ERR_SUCCESS) continue;
        syslog (LOG_ERR, "mosquitto_reconnect failed: (%d) %s", rslt, mosquitto_strerror (rslt));
        if (k == 10) raise (SIGTERM);
    }
    char payload[10]; payload[9] = '\0';
    strncpy (payload, str.c_str(), 9);
    syslog (LOG_DEBUG, "topic=\"%s\" payload=\"%s..\"", g_mqtt_topic, payload);
}

static void
jsonify_generic (const le_advertising_info *info, json *rslt)
{
    char bdaddr[18];
    ba2str (&info->bdaddr, bdaddr);
    json obj = {{"bdaddr", bdaddr},
                {"beacon_type", "generic"}};

    json seq = json::array ();
    const uint8_t* data = info->data;
    for (int i = 0; i < info->length;)
    {
        uint8_t len = data[i];
        uint8_t ad_type = data[++i];

        json ad_data = json::array ();
        for (int j = 1; j < len; j++)
            ad_data.push_back (data[i + j]);
        json elt = {{"ad_type", ad_type}, {"ad_data", ad_data}};
        seq.push_back (elt);

        i += len;
    }
    obj["ad_structures"] = seq;

    *rslt = json (obj);
}

static void
jsonify_ibeacon (const le_advertising_info *info, json *rslt)
{
    char bdaddr[18];
    ba2str (&info->bdaddr, bdaddr);
    json obj = {{"bdaddr", bdaddr},
                {"beacon_type", "ibeacon"}};

    json seq = json::array ();
    ble_beacon_ibeacon ibeacon;
    ble_parse_advertising_data_ibeacon (info, &ibeacon);
    char uuid_str[37];
    uuid_unparse (ibeacon.uuid, uuid_str);
    json elt = {{"ad_type", 0xff},
                {"uuid", uuid_str},
                {"major", ibeacon.major},
                {"minor", ibeacon.minor},
                {"rssi", ibeacon.rssi}};
    seq.push_back (elt);

    obj["ad_structures"] = seq;

    *rslt = json (obj);
}

// mosquitto callbacks
// notifier recognizes "watchdog/ping" messages from watchpup, and responds with "watchdog/pong"
static void
mosq_on_message (struct mosquitto *mosq, void *user, const struct mosquitto_message *msg)
{
    if (!msg) return;
    if (!g_watchdog_enabled || strcmp (msg->topic, "watchdog/ping")) return;

    syslog (LOG_NOTICE, "%s", msg->topic);

    time_t t;
    time (&t);
    uint64_t t64 = (uint64_t)t;
    //uint64_t t64 = 0;
    char resp[200];
    snprintf (resp, 200,
              "{\"time\":%"PRIu64",\"process\":{\"name\":\"%s\",\"host\":\"%s\",\"pid\":%d}}",
              t64, g_program, g_machine, g_pid);
    int rslt = mosquitto_publish (mosq, NULL, "watchdog/pong", strlen (resp) + 1, resp, 0, false);
      // mosq, msg_id, topic, len, payload, qos, retain
    if (rslt != MOSQ_ERR_SUCCESS)
    {
        syslog (LOG_ERR, "mosq_on_message failed: (%d) %s", rslt, mosquitto_strerror (rslt));
    }
}

static void
mosq_on_disconnect (struct mosquitto *mosq, void *user, int reason)
{
    if (reason == 0) return; // mosquitto_disconnect call

    syslog (LOG_NOTICE, "mosquitto disconnected (%d)", reason);

    int rslt = mosquitto_reconnect (mosq);
    if (rslt != MOSQ_ERR_SUCCESS)
    {
        syslog (LOG_ERR, "mosquitto_reconnect failed: (%d) %s", rslt, mosquitto_strerror (rslt));
        raise (SIGTERM);
    }
    syslog (LOG_NOTICE, "mosquitto reconnected");
}
