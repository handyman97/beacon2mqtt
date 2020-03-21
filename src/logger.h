//
// (C) handyman97 (https://github.com/handyman97)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//

#ifndef _LOGGER_H
#define _LOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

#define syslog(...) _syslog (__VA_ARGS__)

// wrapper of the common syslog function
void _syslog (int, const char*, ...);

#ifdef __cplusplus
}
#endif

#endif
