//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#ifndef _BLE_BEACON_H
#define _BLE_BEACON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <stdbool.h>

// this is a small library for BLE beacon broadcasting and passive scanning

// ibeacon (apple)
// 2 ad-structures
struct ble_beacon_ibeacon
{
    //uint8_t length;		// 26
    //uint8_t ad_type;		// 0xff
    //uint16_t company_code;	// 0x004c (LE)
    //uint16_t beacon_code;	// 0x0215 (BE)
    uint8_t uuid[16];		// (BE)
    uint16_t major, minor;	// (BE)
    uint8_t rssi;
};

int ble_set_advertising_data_ibeacon (int socket, struct ble_beacon_ibeacon*);
int ble_parse_advertising_data_ibeacon (const le_advertising_info*, struct ble_beacon_ibeacon*);
bool ble_check_advertising_data_ibeacon (le_advertising_info*);

// eddystone (google)
// 3 ad-structures
struct ble_beacon_eddystone
{
    //uint8_t length;		// 23
    //uint8_t ad_type;		// 0x16
    uint8_t uuid[2];		// aa-fe (BE)
    union
    {
        uint8_t frame[20];
        struct
        {
            uint8_t type;
            uint8_t power;
            uint8_t namespace_id[10];
            uint8_t instance_id[6];
            uint16_t rfu;
        }   uid;
        struct
        {
            uint8_t type;
            uint8_t power;
            uint8_t ephemeral_id[8];
        }   eid;
        struct
        {
            uint8_t type;
            uint8_t power;
            uint8_t prefix;
            uint8_t url[17];
        }   url;
        struct
        {
            uint8_t type;
            uint8_t version;
            uint16_t battery;
            uint16_t temperature;
            uint32_t count;
            uint32_t time;
        }   tlm;
    };
};

// altbeacon (radius network)
// https://github.com/AltBeacon/spec
struct ble_beacon_altbeacon
{
    uint16_t company_code;	// manufacturer (LE)
    //uint16_t beacon_code;	// 0xbeac (BE)
    uint8_t id[20];		// beacon id (BE)
    uint8_t rssi;		// 0-127
    uint8_t reserved;
};

// geobeacon (tecno-world)


// low-level beacon-processing functions
// mostly similar or almost identical with those in bluetooth/hci{,_lib}.h

int ble_open_device (bdaddr_t *bdaddr, int *dev_id, int *socket);
int ble_close_device (int socket);

// SET_ADVERTISING_PARAMETERS (0x0006)
int ble_set_advertising_params (int socket, le_set_advertising_parameters_cp*);
// SET_ADVERTISING_DATA (0x0008)
int ble_set_advertising_data (int socket, le_set_advertising_data_cp*);
// SET_ADVERTISE_ENABLE (0x000A)
int ble_set_advertise_enable (int socket, bool);

// passive sanning
// cf. hcitool --lescan (https://kernel.googlesource.com/pub/scm/bluetooth/bluez/+/5.6/tools/hcitool.c)

// LE_SET_SCAN_PARAMETERS (0x000B)
int ble_set_scan_params (int socket, le_set_scan_parameters_cp*);
// LE_SET_SCAN_ENABLE (0x000C)
int ble_set_scan_enable (int socket, bool, uint8_t);

// scan (blocking)
int ble_scan_advertising_devices (int socket, unsigned int timeout, void (*callback)(le_advertising_info *));


#ifdef __cplusplus
}
#endif

#endif
