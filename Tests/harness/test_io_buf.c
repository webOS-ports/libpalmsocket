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
 * Unit tests for the internal psl_io_buf helpers, including the
 * ILP32 signed/unsigned arithmetic paths.
 */
#include <stdbool.h>
#include <string.h>

#include "psl_io_buf.h"

#include "test_common.h"

int
main(void)
{
    PslIOBuf buf;

    TCHECK(0 == psl_io_buf_init(&buf, 64));
    TCHECK(64 == psl_io_buf_get_max_capacity(&buf));
    TCHECK(psl_io_buf_is_empty(&buf));

    /// Reserve space, fill it, verify content via data ptr
    ssize_t sz = -1;
    void* p = psl_io_buf_reset_set_size(&buf, 16, &sz);
    TCHECK(p && 16 == sz);
    memset(p, 'A', 16);
    TCHECK(16 == psl_io_buf_get_data_size(&buf));

    /// Consume part of the data
    p = psl_io_buf_consume(&buf, 4, &sz);
    TCHECK(p && 12 == sz);
    TCHECK('A' == *(char*)p);
    TCHECK(12 == psl_io_buf_get_data_size(&buf));

    /// Extend within limits
    p = psl_io_buf_extend_if_possible(&buf, 8, &sz);
    TCHECK(p && 20 == sz);
    TCHECK(20 == psl_io_buf_get_data_size(&buf));
    TCHECK('A' == *(char*)p);

    /// Extend beyond max: must be clamped to max capacity
    p = psl_io_buf_extend_if_possible(&buf, 1000, &sz);
    TCHECK(p && 64 == sz);
    TCHECK(64 == psl_io_buf_get_data_size(&buf));

    /// Extend at max: no growth
    p = psl_io_buf_extend_if_possible(&buf, 5, &sz);
    TCHECK(p && 64 == sz);

    /// Truncate down and verify preserved prefix
    p = psl_io_buf_truncate_data(&buf, 8);
    TCHECK(p != NULL);
    TCHECK(8 == psl_io_buf_get_data_size(&buf));
    TCHECK('A' == *(char*)p);

    /// Reset clears
    psl_io_buf_reset_data(&buf);
    TCHECK(psl_io_buf_is_empty(&buf));
    TCHECK(NULL == psl_io_buf_get_data_ptr(&buf, &sz));
    TCHECK(0 == sz);

    /// Consume-then-extend past capacity exercises the memmove
    /// compaction path in psl_io_buf_extend_if_possible
    p = psl_io_buf_reset_set_size(&buf, 60, &sz);
    TCHECK(p && 60 == sz);
    memset(p, 'B', 60);
    p = psl_io_buf_consume(&buf, 30, &sz);
    TCHECK(p && 30 == sz);
    p = psl_io_buf_extend_if_possible(&buf, 20, &sz);
    TCHECK(p && 50 == sz);
    TCHECK('B' == ((char*)p)[0] && 'B' == ((char*)p)[29]);

    psl_io_buf_uninit(&buf);

    return TEST_REPORT("test_io_buf");
}
