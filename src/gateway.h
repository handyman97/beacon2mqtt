//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#ifndef _NOTIFIER_H
#define _NOTIFIER_H

#include <cstdint>
#include <list>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <mosquitto.h>
#include <nlohmann/json.hpp>

namespace gateway
{

struct scanner_params
{
    const char *device = nullptr;
    bdaddr_t *bdaddr = nullptr;

    // BLE scan params
    uint16_t lescan_interval = 10;
    uint8_t lescan_own_type = 0;	// 0:public, 1:random
    uint8_t lescan_scan_type = 0;	// 0:passive, 1:active
    uint8_t lescan_filter_policy = 0;	// 0:none, 1:whitelist (cf. "hcitool lewladd ...")
    uint8_t lescan_filter_type = 0;	// 'g': general, 'l':limited
    uint8_t lescan_filter_dup = 0;	// 0:allow dup, 1:discard dup -- for SET_SCAN_ENABLE (enable, filter_dup)
};

struct notifier_params
{
    // MQTT
    const char *mqtt_host = "localhost";
    unsigned int mqtt_port = 1883;
    const char *mqtt_topic = "beacon";

    // for beacon filtering (on the notifier side)
    // note: these filtering functions are independent of those built into the BLE protocol stack.
    std::list<const char*> *whitelist = nullptr;
    std::list<const char*> *beacon_types = nullptr;
    unsigned int cutoff_duration = 30;

    // formatting
    bool json_generic = false;

    // watchdog
    // if activated, we'll subscribe to "watchdog/ping" and respond to each ping by pong.
    bool watchdog_enabled = false;
    // process info
    const char *program = nullptr;
    const char *machine = nullptr;
    pid_t pid = 0;
};

//
void setup (const scanner_params*, const notifier_params*);

void start (void);

void stop (void);

void terminate (void);

}

#endif
