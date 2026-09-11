/* @@@LICENSE
*
*      Copyright (c) 2026 Herman van Hazendonk <github.com@herrie.org>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* LICENSE@@@ */

/**
 * Minimal test framework shared by the libpalmsocket test harness.
 */
#ifndef PSL_TEST_COMMON_H__
#define PSL_TEST_COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int gTestFailures = 0;
static int gTestChecks = 0;

#define TCHECK(cond) do {                                               \
        gTestChecks++;                                                  \
        if (!(cond)) {                                                  \
            gTestFailures++;                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n",                         \
                    __FILE__, __LINE__, #cond);                         \
        }                                                               \
    } while (0)

#define TCHECK_MSG(cond, ...) do {                                      \
        gTestChecks++;                                                  \
        if (!(cond)) {                                                  \
            gTestFailures++;                                            \
            fprintf(stderr, "FAIL %s:%d: %s: ",                         \
                    __FILE__, __LINE__, #cond);                         \
            fprintf(stderr, __VA_ARGS__);                               \
            fprintf(stderr, "\n");                                      \
        }                                                               \
    } while (0)

#define TEST_REPORT(name) ({                                            \
        printf("%s: %d checks, %d failures -- %s\n", (name),            \
               gTestChecks, gTestFailures,                              \
               gTestFailures ? "FAILED" : "ok");                        \
        gTestFailures ? 1 : 0;                                          \
    })

#endif // PSL_TEST_COMMON_H__
