//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#ifndef _FILTERS_H
#define _FILTERS_H

#include <functional>
#include <list>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

namespace gateway
{

le_advertising_info* filter_by_senders (le_advertising_info*, std::list<const char*>*);

le_advertising_info* filter_by_formats (le_advertising_info*, std::list<const char*>*);

le_advertising_info* drop_if_duplicate (le_advertising_info*, unsigned int);

}

#endif
