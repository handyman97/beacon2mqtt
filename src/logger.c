//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

// define your own version of _syslog elsewhere
// unless you need to resort to the following fallback version.

#if 0
//#if 1

#include "logger.h"
#include <stdarg.h>
#include <syslog.h>

// fallback
void
_syslog (int prio, const char* fmt, ...)
{
    va_list ap;
    va_start (ap, fmt);
    vsyslog (prio, fmt, ap);
    va_end (ap);
}

#endif
