//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#include <syslog.h>
#include <unordered_map>

#include "ble_beacon.h"
#include "filters.h"
#include "logger.h"

//
le_advertising_info*
gateway::filter_by_senders (le_advertising_info* info, std::list<const char*>* whitelist)
{
    if (!info || !whitelist) return (nullptr);

    syslog (LOG_DEBUG, "filter_by_senders: #senders==%d", whitelist->size ());

    char bdaddr[18];
    ba2str (&info->bdaddr, bdaddr);

    for (auto sender : *whitelist)
    {
        //if (strcmp (sender, "any") == 0) return (info);
        if (strcmp (sender, bdaddr) == 0) return (info);
    }

    return (nullptr);
}

//
le_advertising_info*
gateway::filter_by_formats (le_advertising_info* info, std::list<const char*>* formats)
{
    if (!info || !formats) return (nullptr);

    syslog (LOG_DEBUG, "filter_by_formats: #format=%d", formats->size ());

    for (auto format : *formats)
    {
        //if (strcmp (format, "any") == 0) return (info);
        if (strcmp (format, "ibeacon") == 0)
        {
            if (ble_check_advertising_data_ibeacon (info)) return (info);
        }
    }

    return (nullptr);
}

// for detecting/discarding duplicate beacons
le_advertising_info* previous = nullptr;
struct cache_elt { time_t t; bdaddr_t bdaddr; uint8_t length; uint8_t data[31]; };

// info will be dropeed
// if the previous beacon (from the same device as info) is identicqal with info,
std::unordered_map<std::string, cache_elt*> g_cache;
//unsigned int g_cache_duration = 3;	// cache the beacons that have been scanned in the last <3> sec.

le_advertising_info*
gateway::drop_if_duplicate (le_advertising_info* info, unsigned int cutoff_duration)
{
    if (!info) return (nullptr);

    syslog (LOG_DEBUG, "drop_if_duplicate (cache=%d)", g_cache.size ());

    time_t t;
    time (&t);

    char bdaddr_raw[18];
    ba2str (&info->bdaddr, bdaddr_raw);
    std::string bdaddr (bdaddr_raw);

    //if (!g_cache.contains (bdaddr)) // c++20
    if (g_cache.count (bdaddr) == 0)
    {
        cache_elt* elt = (cache_elt*) malloc (sizeof (cache_elt));
        elt->t = t;
        memcpy (elt->bdaddr.b, info->bdaddr.b, 6);
        elt->length = info->length;
        memcpy (elt->data, info->data, info->length);
        g_cache.emplace (bdaddr, elt);
        return (info);
    }

    // g_cache contains bdaddr

    cache_elt* elt = g_cache.at (bdaddr);
    time_t t_prev = elt->t;
    elt->t = t;

    // compare elt w. info
    if (!memcmp (elt->bdaddr.b, info->bdaddr.b, 6)
        && elt->length == info->length
        && !memcmp (elt->data, info->data, elt->length))

        return ((t - t_prev <= cutoff_duration) ? nullptr : info);

    // elt != info
    memcpy (elt->bdaddr.b, info->bdaddr.b, 6);
    memcpy (elt->data, info->data, info->length);
    return (info);
}

#if 0
// info will be dropeed
// if there exists any identical element in the cache
std::list<cache_elt*> g_cache;
le_advertising_info*
drop_if_duplicate (le_advertising_info* info)
{
    if (!info) return (nullptr);

    syslog (LOG_DEBUG, "drop_if_duplicate (cache=%d)", g_cache.size ());

    time_t t;
    time (&t);

    // remote obsolete beacons
    int n = 0;
    for (auto elt : g_cache)
    {
        if (t - elt->t <= g_cache_duration) break;
        n++;
    }
    for (int i = 0; i < n; i++)
    {
        cache_elt* elt = g_cache.front ();
        free (elt);
        g_cache.pop_front ();
    }

    cache_elt* dup = nullptr;
    for (auto elt : g_cache)
    {
        // case elt != info
        // 
        if (memcmp (elt->bdaddr.b, info->bdaddr.b, 6)) continue;
        if (elt->length != info->length) continue;
        if (memcmp (elt->data, info->data, elt->length)) continue;
        // elt = info
        dup = elt;
        g_cache.remove (elt);
        break;
    }    

    if (dup)
    {
        dup->t = t;
        g_cache.push_back (dup);

        syslog (LOG_DEBUG, "drop_if_duplicate: dup found");
        return (nullptr);
    }
    else
    {
        cache_elt* elt = (cache_elt*) malloc (sizeof (cache_elt));
        elt->t = t;
        memcpy (elt->bdaddr.b, info->bdaddr.b, 6);
        elt->length = info->length;
        memcpy (elt->data, info->data, info->length);
        g_cache.push_back (elt);

        syslog (LOG_DEBUG, "drop_if_duplicate: cache grown");
        return (info);
    }
}
#endif
