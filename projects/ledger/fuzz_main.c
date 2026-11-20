/* Copyright 2026 EmptyEmptySet
 * SPDX-License-Identifier: MIT
 * Copied from https://github.com/EmptyEmptySet/SoftwareEngineering/blob/00d62035f9945fba627bc998a24d169e9561828a/fuzz/fuzz_main.c
 * Modified 2026 by EmptyEmptySet: bound the operation count for the OSS Verify driver.
 */
/*
 * libFuzzer target for the ledger's non-interactive core.
 *
 * The fuzzer input is a byte stream of operations. Each operation is one
 * opcode byte followed by its operands. The harness only calls functions that
 * do not read from stdin or print to stdout, so a single input always runs to
 * completion and the same bytes always produce the same sequence of calls.
 *
 * Build with CMake:
 *   cmake -S . -B build-fuzz -DLEDGER_BUILD_FUZZER=ON -DLEDGER_BUILD_TESTS=OFF \
 *         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build-fuzz
 *   ./build-fuzz/fuzz_ledger
 *
 * A standalone driver is available for smoke tests without libFuzzer:
 *   cc -DLEDGER_FUZZ_STANDALONE -Iinclude fuzz/fuzz_main.c src/manager.c \
 *      src/platform.c -o fuzz_standalone
 *   ./fuzz_standalone some-input-file
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"

#define OPERATION_LIMIT 4096

typedef struct FuzzReader {
    const uint8_t *data;
    size_t size;
    size_t position;
} FuzzReader;

enum {
    FUZZ_OP_ADD_RECORD,
    FUZZ_OP_DELETE_RECORD,
    FUZZ_OP_HIDE_RECORD,
    FUZZ_OP_ADD_CATEGORY,
    FUZZ_OP_DELETE_CATEGORY,
    FUZZ_OP_TOGGLE_CATEGORY,
    FUZZ_OP_ASSIGN_CATEGORY,
    FUZZ_OP_SET_FILTER,
    FUZZ_OP_CHECK_FILTER,
    FUZZ_OP_COUNT
};

/* Keep the filter computations observable even with optimisation enabled. */
static volatile double fuzz_sink;

static uint8_t read_u8(FuzzReader *reader)
{
    if (reader->position >= reader->size) {
        return 0;
    }
    return reader->data[reader->position++];
}

static uint32_t read_u32(FuzzReader *reader)
{
    uint32_t value = 0;
    int index;

    for (index = 0; index < 4; ++index) {
        value = (value << 8) | (uint32_t)read_u8(reader);
    }
    return value;
}

static int read_int(FuzzReader *reader)
{
    uint32_t bits = read_u32(reader);
    int value;

    memcpy(&value, &bits, sizeof value);
    return value;
}

static uint64_t read_u64(FuzzReader *reader)
{
    uint64_t value = 0;
    int index;

    for (index = 0; index < 8; ++index) {
        value = (value << 8) | (uint64_t)read_u8(reader);
    }
    return value;
}

static double read_double(FuzzReader *reader)
{
    uint64_t bits = read_u64(reader);
    double value;

    memcpy(&value, &bits, sizeof value);
    return value;
}

static void read_text(FuzzReader *reader, char *buffer, size_t capacity)
{
    size_t length = (size_t)read_u8(reader);
    size_t available = reader->size - reader->position;

    if (length >= capacity) {
        length = capacity - 1;
    }
    if (length > available) {
        length = available;
    }
    if (length > 0) {
        memcpy(buffer, reader->data + reader->position, length);
    }
    reader->position += length;
    buffer[length] = '\0';
}

static Date read_date(FuzzReader *reader)
{
    Date date;

    date.year = read_int(reader);
    date.month = read_int(reader);
    date.day = read_int(reader);
    return date;
}

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    RecordManger manager;
    FuzzReader reader;
    size_t operations = 0;

    if (data == NULL || size == 0) {
        return 0;
    }

    reader.data = data;
    reader.size = size;
    reader.position = 0;

    recordManger_init(&manager, 1000);

    while (reader.position < reader.size && operations < OPERATION_LIMIT) {
        uint8_t opcode = read_u8(&reader);

        ++operations;
        switch (opcode % FUZZ_OP_COUNT) {
        case FUZZ_OP_ADD_RECORD: {
            double amount = read_double(&reader);
            Date time = read_date(&reader);
            bool isPayment = (read_u8(&reader) & 1u) != 0;
            char otherInfo[64];

            read_text(&reader, otherInfo, sizeof otherInfo);
            (void)recordManger_addRecord(&manager, amount, time, otherInfo,
                                         isPayment);
            break;
        }
        case FUZZ_OP_DELETE_RECORD:
            recordManger_deleteRecordByID(&manager, read_int(&reader));
            break;
        case FUZZ_OP_HIDE_RECORD: {
            int ID = read_int(&reader);
            char password[64];

            read_text(&reader, password, sizeof password);
            recordManger_hideRecordWithPassword(&manager, ID, password);
            break;
        }
        case FUZZ_OP_ADD_CATEGORY: {
            char name[64];

            read_text(&reader, name, sizeof name);
            (void)recordManger_addCategory(&manager, name);
            break;
        }
        case FUZZ_OP_DELETE_CATEGORY:
            recordManger_deleteCategoryByID(&manager, read_int(&reader));
            break;
        case FUZZ_OP_TOGGLE_CATEGORY:
            recordManger_toggleCategoryVaild(&manager, read_int(&reader));
            break;
        case FUZZ_OP_ASSIGN_CATEGORY: {
            int ID = read_int(&reader);
            int CID = read_int(&reader);

            recordManger_setRecordCategory(&manager, ID, CID);
            break;
        }
        case FUZZ_OP_SET_FILTER: {
            Date startTime = read_date(&reader);
            Date endTime = read_date(&reader);
            double lowAmount = read_double(&reader);
            double highAmount = read_double(&reader);

            recordManger_setFilter(&manager, startTime, endTime, lowAmount,
                                   highAmount);
            break;
        }
        case FUZZ_OP_CHECK_FILTER: {
            size_t index;

            for (index = 0; index < manager.records.size; ++index) {
                Record *record = &manager.records.entries[index].value;
                if (record->isHidden == false &&
                    filter_check(&manager.filter, record)) {
                    fuzz_sink += record->amount;
                }
            }
            break;
        }
        default:
            break;
        }
    }

    recordManger_free(&manager);
    return 0;
}

#ifdef __cplusplus
}
#endif

#ifdef LEDGER_FUZZ_STANDALONE
static int run_file(const char *path)
{
    FILE *file;
    long length;
    uint8_t *buffer;
    size_t readBytes;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Cannot open %s\n", path);
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    length = ftell(file);
    if (length < 0) {
        fclose(file);
        return 0;
    }
    rewind(file);

    if (length == 0) {
        fclose(file);
        return 0;
    }

    buffer = (uint8_t *)malloc((size_t)length);
    if (buffer == NULL && length > 0) {
        fclose(file);
        return 0;
    }

    readBytes = fread(buffer, 1, (size_t)length, file);
    fclose(file);

    (void)LLVMFuzzerTestOneInput(buffer, readBytes);
    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    int index;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s INPUT [INPUT ...]\n", argv[0]);
        return 1;
    }
    for (index = 1; index < argc; ++index) {
        (void)run_file(argv[index]);
    }
    return 0;
}
#endif
