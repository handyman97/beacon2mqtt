//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

// Refs
// - https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/
// - https://kernel.googlesource.com/pub/scm/bluetooth/bluez/+/5.6/tools/hcitool.c
//
// - https://developer.apple.com/ibeacon/Getting-Started-with-iBeacon.pdf
// - https://gfiber.googlesource.com/vendor/google/platform/+/master/cmds/ibeacon.c
// - https://github.com/carsonmcdonald/bluez-ibeacon

#include "ble_beacon.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

int
ble_open_device (bdaddr_t *bdaddr, int *dev_id, int *socket)
{
    *dev_id = hci_get_route (bdaddr);
    if (*dev_id < 0) return (-1);

    *socket = hci_open_dev (*dev_id);
    if (*socket < 0) return (-1);

    return (0);
}

int
ble_close_device (int socket)
{
    hci_close_dev(socket);
    return (0);
}

int
ble_set_advertising_params (int socket, le_set_advertising_parameters_cp* adv_params_cp)
{
    // -----------------------------------
    // SET_ADVERTISING_PARAMETERS (0x0006)
    // -----------------------------------
    // typedef struct {
    //   uint16_t        min_interval;
    //   uint16_t        max_interval;
    //   uint8_t         advtype;
    //   uint8_t         own_bdaddr_type;
    //   uint8_t         direct_bdaddr_type;
    //   bdaddr_t        direct_bdaddr;
    //   uint8_t         chan_map;
    //   uint8_t         filter;
    // } __attribute__ ((packed)) le_set_advertising_parameters_cp;
    uint8_t status;
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    // struct hci_request {
    //     uint16_t ogf;
    //     uint16_t ocf;
    //     int      event;
    //     void     *cparam;
    //     int      clen;
    //     void     *rparam;
    //     int      rlen;
    // };
    rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
    rq.cparam = &adv_params_cp;
    rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    // hci_send_req OGF_LE_CTL OCF_LE_SET_ADVERTISING_PARAMETERS
    int rslt = hci_send_req (socket, &rq, 1000);
    if (rslt < 0)
        syslog (LOG_ERR, "[ble_set_advertising_params] %s (%d)", strerror (errno), errno);

    return (rslt);
}

// int
// ble_set_advertising_params (int socket, int interval_min, int interval_max)
// {
//     le_set_advertising_parameters_cp adv_params_cp;
//     memset(&adv_params_cp, 0, sizeof(adv_params_cp));
//     adv_params_cp.min_interval = htobs(interval_min);
//     adv_params_cp.max_interval = htobs(interval_max);
//     adv_params_cp.chan_map = 7;
// 
//     return (ble_set_advertising_params (socket, &adv_params_cp));
// }

int
ble_set_advertise_enable (int socket, bool enabling)
{
    // -----------------------------
    // SET_ADVERTISE_ENABLE (0x000a)
    // -----------------------------
    // typedef struct {
    //   uint8_t         enable;
    // } __attribute__ ((packed)) le_set_advertise_enable_cp;

    uint8_t status;
    struct hci_request rq;

    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));
    advertise_cp.enable = enabling ? 1 : 0;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
    rq.cparam = &advertise_cp;
    rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    // hci_send_req OGF_LE_CTL OCF_LE_SET_ADVERTISE_ENABLE
    int rslt = hci_send_req(socket, &rq, 1000);
    if (rslt < 0)
        syslog (LOG_ERR, "[ble_set_advertise_enable] %s (%d)", strerror(errno), errno);

    return (rslt);
}

// int
// ble_set_advertise_disable (int socket)
// {
//     uint8_t status;
//     le_set_advertise_enable_cp advertise_cp;
//     // typedef struct {
//     //   uint8_t         enable;
//     // } __attribute__ ((packed)) le_set_advertise_enable_cp;
//     memset(&advertise_cp, 0, sizeof(advertise_cp));
//     advertise_cp.enable = 0x00;
// 
//     struct hci_request rq;
//     memset(&rq, 0, sizeof(rq));
//     rq.ogf = OGF_LE_CTL;
//     rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
//     rq.cparam = &advertise_cp;
//     rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
//     rq.rparam = &status;
//     rq.rlen = 1;
// 
//     int rslt = hci_send_req(socket, &rq, 1000);
//     if (rslt < 0)
//         syslog (LOG_ERR, "Can't send request %s (%d)\n", strerror(errno), errno);
// 
//     return (rslt);
// }

int
ble_set_advertising_data (int socket, le_set_advertising_data_cp* adv_data_cp)
{
    // -----------------------------
    // SET_ADVERTISING_DATA (0x0008)
    // -----------------------------
    // le_set_advertising_data_cp adv_data_cp;
    // struct {
    //   uint8_t         length;
    //   uint8_t         data[31];
    // } __attribute__ ((packed)) le_set_advertising_data_cp;

    uint8_t status;
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
    rq.cparam = adv_data_cp;
    rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    // hci_send_req OGF_LE_CTL OCF_LE_SET_ADVERTISING_DATA
    int rslt = hci_send_req(socket, &rq, 1000);
    if (rslt < 0)
        syslog (LOG_ERR, "[ble_set_advertising_data] %s (%d)", strerror(errno), errno);

    return (rslt);
}

int
ble_set_scan_params (int socket, le_set_scan_parameters_cp* scan_params_cp)
{
    // ----------------------------
    // SET_SCAN_PARAMETERS (0x000B)
    // ----------------------------
    // struct {
    //   uint8_t         type;
    //   uint16_t        interval;
    //   uint16_t        window;
    //   uint8_t         own_bdaddr_type;
    //   uint8_t         filter;
    // } __attribute__ ((packed)) le_set_scan_parameters_cp;
    uint8_t status;
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_PARAMETERS;
    rq.cparam = &scan_params_cp;
    rq.clen = LE_SET_SCAN_PARAMETERS_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    // hci_send_req OGF_LE_CTL OCF_LE_SET_SCAN_PARAMETERS
    int rslt = hci_send_req (socket, &rq, 1000);
    if (rslt < 0)
        syslog (LOG_ERR, "[ble_set_scan_params] %s (%d)", strerror (errno), errno);

    return (rslt);
}

int
ble_set_scan_enable (int socket, bool enable, uint8_t filter_dup)
{
    // -----------------------------
    // SET_SCAN_ENABLE (0x000C)
    // -----------------------------
    // typedef struct {
    //   uint8_t         enable;
    //   uint8_t         filter_dup;
    // } __attribute__ ((packed)) le_set_scan_enable_cp;
    uint8_t status;
    struct hci_request rq;

    le_set_scan_enable_cp scan_cp;
    memset (&scan_cp, 0, sizeof (scan_cp));
    scan_cp.enable = enable ? 1 : 0;
    scan_cp.filter_dup = filter_dup;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_SCAN_ENABLE;
    rq.cparam = &scan_cp;
    rq.clen = LE_SET_SCAN_ENABLE_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    // hci_send_req OGF_LE_CTL OCF_LE_SET_SCAN_ENABLE
    int rslt = hci_send_req(socket, &rq, 1000);
    if (rslt < 0)
        syslog (LOG_ERR, "[ble_set_scan_enable] %s (%d)", strerror(errno), errno);

    return (rslt);
}

int
ble_scan_advertising_devices (int dd, unsigned int timeout, void (*callback)(le_advertising_info *))
{
    // back up the current socketopt
    struct hci_filter of;
    socklen_t olen;
    olen = sizeof(of);
    if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0)
    {
        //printf("Could not get socket options\n");
        syslog (LOG_ERR, "ble_scan_advertising_devices: (%d) %s", errno, strerror (errno));
        return -1;
    }

    struct hci_filter nf;
    hci_filter_clear(&nf);
    hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
    hci_filter_set_event(EVT_LE_META_EVENT, &nf);
    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
    {
        syslog (LOG_ERR, "ble_scan_advertising_devices: (%d) %s", errno, strerror (errno));
        return -1;
    }

    // non-blocking read
    //int opt = 1;
    //ioctl (dd, FIONBIO, &opt);

    unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
    int len;
    time_t t0, t;
    time (&t0);
    //syslog (LOG_INFO, "ble_scan_advertising_devices loop (%us)", timeout);
    while (1)
    {
        //time (&t); if (t - t0 > timeout) goto done;

#if 0
        // non-blocking read
        struct timespec tspec = {0, 10000000};	// 10ms
        while ((len = read(dd, buf, sizeof(buf))) < 0)
        {
            if (errno == EAGAIN)
            {
                time (&t);
                if (timeout > 0 && t - t0 >= (unsigned int)timeout) goto done;

                nanosleep (&tspec);	// 10ms
                continue;
            }
            if (errno == EINTR) continue;
            goto done;
        }
#else
        // blocking read
        len = read(dd, buf, sizeof(buf));
        if (len < 0) break;
        time (&t);
        if (timeout > 0 && t - t0 >= (unsigned int)timeout) break;
#endif
        t0 = t;

        ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
        len -= (1 + HCI_EVENT_HDR_SIZE);
        evt_le_meta_event *meta = (evt_le_meta_event *) ptr;
        // typedef struct {
        //   uint8_t         subevent;
        //   uint8_t         data[0];
        // } __attribute__ ((packed)) evt_le_meta_event;
        if (meta->subevent != EVT_LE_ADVERTISING_REPORT) break;

        le_advertising_info *info = (le_advertising_info *) (meta->data + 1);
        (*callback)(info);
    }

 done:
    //fprintf (stderr, "[ble_scan_advertising_devices] loop done (%u)\n", (uint64_t)t);
    setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
    if (len < 0)
    {
        syslog (LOG_ERR, "ble_scan_advertising_devices failed: (%d) %s", errno, strerror (errno));
        return -1;
    }
    return 0;
}

// extras

int
ble_set_advertising_data_ibeacon (int socket, struct ble_beacon_ibeacon *ibeacon)
{
    le_set_advertising_data_cp adv_data_cp;
    // struct { uint8_t length; uint8_t data[31]; }
    memset(&adv_data_cp, 0, sizeof(adv_data_cp));

    adv_data_cp.length = 30;

    // ad_structure = { uint8_t length; uint8_t ad_type; uint8_t ad_data[length - 1]; }
    // cf. https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/

    // ad_structure1 (1+2 bytes)
    adv_data_cp.data[0] = 2;			// length
    adv_data_cp.data[1] = htobs(0x01);		// ad_type: "flags"
    adv_data_cp.data[2] = htobs(0b00000110);	// ad_data: flag value
    //adv_data_cp.data[2] = htobs(0b00011010);	// ad_data: flag value
      // 0001-0000: Simultaneous LE and BR/ERD to Same Device Capable(Host)
      // 0000-1000: Simultaneous LE and BR/ERD to Same Device Capable(Controller)
      // 0000-0100: BR/EDR Not Supported
      // 0000-0010: LE General Discoverable Mode
      // 0000-0001: LE Limited Discoverable Mode

    // ad_structure2 (1+26 bytes)
    const int offset = 3;
    adv_data_cp.data[offset + 0] = 26;		// length
    adv_data_cp.data[offset + 1] = 0xff;	// ad_type: "manufacturer-specific"
    // company id (apple = 4c 00)
    adv_data_cp.data[offset + 2] = htobs(0x4C);
    adv_data_cp.data[offset + 3] = htobs(0x00);
    // beacon type (0x0215)
    adv_data_cp.data[offset + 4] = htobs(0x02);
    adv_data_cp.data[offset + 5] = htobs(0x15);
    // uuid (16bytes)
    memcpy (adv_data_cp.data + offset + 6, ibeacon->uuid, 16);
    // Major number (2bytes)
    int16_t major_number = ibeacon->major;
    adv_data_cp.data[offset + 22] = htobs(major_number >> 8 & 0x00FF);
    adv_data_cp.data[offset + 23] = htobs(major_number & 0x00FF);
    // Minor number (2bytes)
    int16_t minor_number = ibeacon->minor;
    adv_data_cp.data[offset + 24] = htobs(minor_number >> 8 & 0x00FF);
    adv_data_cp.data[offset + 25] = htobs(minor_number & 0x00FF);
    // signal power
    int8_t power = ibeacon->rssi;
    adv_data_cp.data[offset + 26] = htobs((power < 0) ? (power + (2 << 7)) : power);

    //
    int rslt = ble_set_advertising_data (socket, &adv_data_cp);
    if (rslt != 0)
        syslog (LOG_ERR, "[ble_set_advertising_data_ibeacon] %s (%d)", strerror(errno), errno);

    return (rslt);
}

int
ble_parse_advertising_data_ibeacon (const le_advertising_info* info, struct ble_beacon_ibeacon* ibeacon)
{
    if (!info || !ibeacon) return (-1);

    // typedef struct
    // {
    //     uint8_t         evt_type;
    //     uint8_t         bdaddr_type;
    //     bdaddr_t        bdaddr;
    //     uint8_t         length;
    //     uint8_t         data[0];
    // } __attribute__ ((packed)) le_advertising_info;
    const uint8_t* data = info->data;
    for (int i = 0; i < info->length;)
    {
        uint8_t len = data[i]; // =26
        uint8_t ad_type = data[++i];
        if (ad_type == 0xff)
        {
            // company id (0x4c00)
            if (data[i + 1] != 0x4c || data[i + 2] != 0x00) goto invalid;
            // beacon type (0x0215)
            if (data[i + 3] != 0x02 || data[i + 4] != 0x15) goto invalid;
            // uuid (16bytes)
            memcpy (ibeacon->uuid, data + i + 5, 16);
            // major (2bytes)
            ibeacon->major = ((uint16_t)data[i + 21] << 8) + data[i + 22];
            // minor (2bytes)
            ibeacon->minor = ((uint16_t)data[i + 23] << 8) + data[i + 24];
            // power (1byte)
            ibeacon->rssi = data[i + 25];

            return (0);
        }
        i += len;
    }

 invalid:
    return (-1);
}

bool
ble_check_advertising_data_ibeacon (le_advertising_info* info)
{
    if (!info) return (false);

    // 2 ad-structures
    uint8_t* data = info->data;

    for (int i = 0; i < info->length;)
    {
        uint8_t len = data[i]; // =26
        uint8_t ad_type = data[++i];
        if (ad_type == 0xff)
        {
            // company id (0x4c00)
            if (data[i + 1] != 0x4c || data[i + 2] != 0x00) break;
            // beacon type (0x0215)
            if (data[i + 3] != 0x02 || data[i + 4] != 0x15) break;

            return (true);
        }
        i += len;
    }

    return (false);
}

// deprecated
/*
static int uuid_encode (const char* uuid, uint8_t* data);
static int uuid_decode (uint8_t* data, char* uuid);

static int
uuid_encode (const char* uuid, uint8_t* data)
{
    if (!uuid || !data) return (-1);

    char conv[] = "0123456789ABCDEF";
    int len = strlen(uuid);
    int n = 0;
    for (int i = 0; i < strlen (uuid); i++)
    {
        while (!isalnum (uuid[i])) i++;
        char hi = strchr (conv, toupper (uuid[i])) - conv;
        i++;
        while (!isalnum (uuid[i])) i++;
        char lo = strchr (conv, toupper (uuid[i])) - conv;
        data[n++] = 0x10 * hi + lo;
    }

    if (n != 16) return (-1);
    return (0);
}

static int
uuid_decode (uint8_t* data, char* uuid)
{
    if (!uuid || !data) return (-1);

    for (int i = 0; i < 16; i++)
    {
        sprintf (uuid + 2 * i, "%02x", data[i]);
    }
    uuid[32] = '\0';

    return (0);
}
*/
