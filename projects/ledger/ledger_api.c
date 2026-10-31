/* Copyright 2026 EmptyEmptySet
 * SPDX-License-Identifier: Apache-2.0
 *
 * ledger_api: the ledger's record, category and filter API, driven by a byte stream.
 *
 * The fuzz input is a sequence of operations. Each operation selects one API call and its arguments:
 * the strings, amounts, dates, payment flags and object indices all come from the input. The target keeps
 * the IDs that the API returned and its own expected state, so every check compares the library with a
 * model that comes from the input and the documented API rules, not from the library's internal state.
 *
 * Properties, each an `if (!condition) abort();` after the calls:
 *   map_shape           the ordered maps hold exactly the objects the target created, each under its own
 *                       ID or CID, with strictly increasing keys and size at most capacity.
 *   strings_terminated  every fixed-size text field (info, password, category name) has a NUL in its array.
 *   add_contract        addRecord returns one more than the old ID, stores the record under that ID, and
 *                       stores the amount, date, payment flag, truncated info, CID 0, hidden false and the
 *                       validity the target expects for category 0.
 *   delete_contract     deleting an existing record removes it and leaves the expected number of records.
 *   hide_contract       hiding a fresh record sets its hidden flag and stores the truncated password; a
 *                       second hide leaves the password alone.
 *   category_consistency every record has the CID and Cvaild flag that the target's model expects, and its
 *                       category exists with the expected validity.
 *   delete_category     deleting a category removes it; each record that named it moves to CID 0 and the
 *                       validity the target expects for category 0.
 *   filter_boundaries   filter_check excludes both date endpoints and includes both amount endpoints.
 *   missing_objects     reading a missing record or category creates a zeroed object.
 *
 * No property depends on a clock, a random number, the environment, a thread or a file.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "manager.h"

#define OBJECT_LIMIT 256
#define OPERATION_LIMIT 512
#define TEXT_CAPACITY 64
#define TEXT_LENGTH 20

typedef struct Reader {
    const uint8_t *data;
    size_t size;
    size_t position;
} Reader;

static uint8_t read_u8(Reader *reader)
{
    if (reader->position >= reader->size) {
        return 0;
    }
    return reader->data[reader->position++];
}

static uint32_t read_u32(Reader *reader)
{
    uint32_t value = 0;
    int index;

    for (index = 0; index < 4; ++index) {
        value = (value << 8) | (uint32_t)read_u8(reader);
    }
    return value;
}

static uint64_t read_u64(Reader *reader)
{
    uint64_t value = 0;
    int index;

    for (index = 0; index < 8; ++index) {
        value = (value << 8) | (uint64_t)read_u8(reader);
    }
    return value;
}

static int32_t read_i32(Reader *reader)
{
    uint32_t bits = read_u32(reader);
    int32_t value;

    memcpy(&value, &bits, sizeof value);
    return value;
}

static double read_double(Reader *reader)
{
    uint64_t bits = read_u64(reader);
    double value;

    memcpy(&value, &bits, sizeof value);
    return value;
}

static void read_text(Reader *reader, char *text, size_t capacity)
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
        memcpy(text, reader->data + reader->position, length);
    }
    reader->position += length;
    text[length] = '\0';
}

/* What copy_text in manager.c stores for a text of the input: the first 19 bytes, or fewer at a NUL. */
static void expected_text(const char *text, char expected[TEXT_LENGTH])
{
    size_t length = strlen(text);

    if (length >= TEXT_LENGTH) {
        length = TEXT_LENGTH - 1;
    }
    memcpy(expected, text, length);
    expected[length] = '\0';
}

static bool contains_id(const int *ids, size_t count, int id)
{
    size_t index;

    for (index = 0; index < count; ++index) {
        if (ids[index] == id) {
            return true;
        }
    }
    return false;
}

static void check_map_shape(const RecordManger *manager, const int *recordIDs,
                            size_t recordCount, const int *categoryIDs,
                            size_t categoryCount)
{
    size_t index;
    bool ok = manager->records.size == recordCount &&
              manager->categorys.size == categoryCount;

    if (manager->records.size > manager->records.capacity) {
        ok = false;
    }
    if (manager->records.size > 0 && manager->records.entries == NULL) {
        ok = false;
    }
    for (index = 0; index < manager->records.size; ++index) {
        const RecordEntry *entry = &manager->records.entries[index];

        if (index > 0 && !(manager->records.entries[index - 1].key < entry->key)) {
            ok = false;
        }
        if (!contains_id(recordIDs, recordCount, entry->key)) {
            ok = false;
        }
        if (entry->key != entry->value.ID) {
            ok = false;
        }
    }

    if (manager->categorys.size > manager->categorys.capacity) {
        ok = false;
    }
    if (manager->categorys.size > 0 && manager->categorys.entries == NULL) {
        ok = false;
    }
    for (index = 0; index < manager->categorys.size; ++index) {
        const CategoryEntry *entry = &manager->categorys.entries[index];

        if (index > 0 && !(manager->categorys.entries[index - 1].key < entry->key)) {
            ok = false;
        }
        if (!contains_id(categoryIDs, categoryCount, entry->key)) {
            ok = false;
        }
        if (entry->key != entry->value.CID) {
            ok = false;
        }
    }

    /* The ordered maps hold exactly the objects the target created, each under its own ID, in
     * strictly increasing key order, and size never exceeds capacity.
     *
     * mutant: src/manager.c:320 `map->entries[position].key = key;` -> `map->entries[position].key = key + 1;`
     * input: add
     */
    if (!ok) {
        abort();
    }
}

static void check_strings(const RecordManger *manager)
{
    size_t index;
    bool ok = true;

    for (index = 0; index < manager->records.size; ++index) {
        const Record *record = &manager->records.entries[index].value;

        if (memchr(record->otherInfo, '\0', sizeof record->otherInfo) == NULL) {
            ok = false;
        }
        if (memchr(record->password, '\0', sizeof record->password) == NULL) {
            ok = false;
        }
    }
    for (index = 0; index < manager->categorys.size; ++index) {
        const Category *category = &manager->categorys.entries[index].value;

        if (memchr(category->name, '\0', sizeof category->name) == NULL) {
            ok = false;
        }
    }

    /* copy_text terminates each fixed-size text field, including the 19-byte case.
     *
     * mutant: src/manager.c:30 `destination[length] = '\0';` -> `destination[length] = 'X';`
     * input: add
     */
    if (!ok) {
        abort();
    }
}

static void check_add_contract(const RecordManger *manager, int id, int oldID,
                               double amount, Date time, const char *info,
                               bool isPayment, bool expectedCvaild)
{
    const Record *record = record_map_find(&manager->records, id);
    char expected[TEXT_LENGTH];
    bool ok;

    expected_text(info, expected);
    ok = id == oldID + 1 && manager->ID == id && record != NULL;
    if (ok) {
        ok = record->ID == id && record->CID == 0 && record->isHidden == false &&
             record->isPayment == isPayment &&
             record->Cvaild == expectedCvaild &&
             record->time.year == time.year && record->time.month == time.month &&
             record->time.day == time.day &&
             memcmp(&record->amount, &amount, sizeof amount) == 0 &&
             strcmp(record->otherInfo, expected) == 0;
    }

    /* addRecord assigns the next ID and record_create fills the new record as documented.
     *
     * mutant: src/manager.c:59 `record.isHidden = false;` -> `record.isHidden = true;`
     * input: add
     */
    if (!ok) {
        abort();
    }
}

static void check_delete_contract(const RecordManger *manager, int id,
                                  size_t expectedSize)
{
    bool ok = manager->records.size == expectedSize &&
              record_map_find(&manager->records, id) == NULL;

    /* Deleting an existing record removes it and leaves the expected number of records.
     *
     * mutant: src/manager.c:347 `--map->size;` -> ``
     * input: delete
     */
    if (!ok) {
        abort();
    }
}

static void check_hide_contract(const Record *record, bool wasHidden,
                                const char *oldPassword, const char *password)
{
    char expected[TEXT_LENGTH];
    bool ok = record->isHidden == true;

    expected_text(password, expected);
    if (ok && wasHidden) {
        ok = strcmp(record->password, oldPassword) == 0;
    }
    if (ok && !wasHidden) {
        ok = strcmp(record->password, expected) == 0;
    }

    /* Hiding sets the flag and the truncated password; hiding again keeps the old password.
     *
     * mutant: src/manager.c:102 `record->isHidden = true;` -> `record->isHidden = false;`
     * input: hide
     */
    if (!ok) {
        abort();
    }
}

static void check_category_consistency(const RecordManger *manager,
                                       const int *recordIDs,
                                       const int *recordCID,
                                       const bool *recordCvaild,
                                       size_t recordCount)
{
    size_t index;
    bool ok = true;

    for (index = 0; index < recordCount; ++index) {
        const Record *record = record_map_find(&manager->records, recordIDs[index]);
        const Category *category;

        if (record == NULL || record->CID != recordCID[index] ||
            record->Cvaild != recordCvaild[index]) {
            ok = false;
            continue;
        }
        category = category_map_find(&manager->categorys, recordCID[index]);
        if (category == NULL || category->Cvaild != recordCvaild[index]) {
            ok = false;
        }
    }

    /* Every record has the CID, Cvaild flag and category validity that the target's model expects.
     *
     * mutant: src/manager.c:561 `record->Cvaild = category->Cvaild;` -> `record->Cvaild = !category->Cvaild;`
     * input: assign
     */
    if (!ok) {
        abort();
    }
}

static void check_delete_category_contract(const RecordManger *manager, int CID,
                                           bool existed, bool categoryZeroValid,
                                           const int *moved, size_t movedCount)
{
    size_t index;
    bool ok = true;

    if (CID == 0) {
        for (index = 0; ok && index < movedCount; ++index) {
            const Record *record = record_map_find(&manager->records, moved[index]);

            if (record == NULL || record->CID != 0 ||
                record->Cvaild != categoryZeroValid) {
                ok = false;
            }
        }
    } else {
        if (existed && category_map_find(&manager->categorys, CID) != NULL) {
            ok = false;
        }
        for (index = 0; ok && index < movedCount; ++index) {
            const Record *record = record_map_find(&manager->records, moved[index]);

            if (record == NULL || record->CID != 0 ||
                record->Cvaild != categoryZeroValid) {
                ok = false;
            }
        }
    }

    /* Deleting a category moves each record that named it to CID 0 and category 0's validity.
     *
     * mutant: src/manager.c:529 `record->CID = 0;` -> `record->CID = 1;`
     * input: delete_category
     */
    if (!ok) {
        abort();
    }
}

static void check_filter_boundaries(void)
{
    Filter filter = filter_create((Date){2000, 1, 1}, (Date){2000, 1, 3},
                                  10.0, 20.0);
    Record record = record_create(1, 10.0, (Date){2000, 1, 2}, "", false, true);
    bool ok;

    ok = filter_check(&filter, &record);
    record.amount = 20.0;
    ok = ok && filter_check(&filter, &record);
    record.amount = 9.5;
    ok = ok && !filter_check(&filter, &record);
    record.amount = 20.5;
    ok = ok && !filter_check(&filter, &record);
    record.amount = 15.0;
    record.time = (Date){2000, 1, 1};
    ok = ok && !filter_check(&filter, &record);
    record.time = (Date){2000, 1, 3};
    ok = ok && !filter_check(&filter, &record);

    /* filter_check excludes both date endpoints and includes both amount endpoints.
     *
     * mutant: src/manager.c:240 `record->amount >= filter->lowAmount` -> `record->amount > filter->lowAmount`
     * input: basic
     */
    if (!ok) {
        abort();
    }
}

static void check_missing_objects(void)
{
    RecordManger probe;
    Record *record;
    Category *category;
    bool ok;

    recordManger_init(&probe, 0);
    record = recordManger_getRecord(&probe, 123456789);
    category = recordManger_getCategory(&probe, 987654321);
    ok = record != NULL && category != NULL &&
         record->ID == 0 && record->CID == 0 && record->isHidden == false &&
         record->Cvaild == false && record->amount == 0.0 &&
         record->otherInfo[0] == '\0' && record->password[0] == '\0' &&
         category->CID == 0 && category->Cvaild == false &&
         category->name[0] == '\0';
    recordManger_free(&probe);

    /* Reading a missing record or category creates a zeroed object.
     *
     * mutant: src/manager.c:321 `memset(&map->entries[position].value, 0, sizeof map->entries[position].value);` -> `memset(&map->entries[position].value, 0xFF, sizeof map->entries[position].value);`
     * input: basic
     */
    if (!ok) {
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    RecordManger manager;
    Reader reader;
    int recordIDs[OBJECT_LIMIT];
    int recordCID[OBJECT_LIMIT];
    bool recordCvaild[OBJECT_LIMIT];
    int categoryIDs[OBJECT_LIMIT];
    bool categoryCvaild[OBJECT_LIMIT];
    size_t recordCount = 0;
    size_t categoryCount = 0;
    size_t operations = 0;

    if (data == NULL) {
        return 0;
    }

    reader.data = data;
    reader.size = size;
    reader.position = 0;
    recordManger_init(&manager, 1000);
    categoryIDs[categoryCount] = 0;
    categoryCvaild[categoryCount] = true;
    ++categoryCount;

    while (reader.position < reader.size && operations < OPERATION_LIMIT) {
        uint8_t opcode = read_u8(&reader);

        ++operations;
        switch (opcode) {
        case 0: {
            double amount = read_double(&reader);
            Date time;
            bool isPayment;
            char info[TEXT_CAPACITY];

            time.year = read_i32(&reader);
            time.month = read_i32(&reader);
            time.day = read_i32(&reader);
            isPayment = (read_u8(&reader) & 1u) != 0;
            read_text(&reader, info, sizeof info);
            if (recordCount < OBJECT_LIMIT) {
                int oldID = manager.ID;
                bool expectedCvaild = categoryCvaild[0];
                int id = recordManger_addRecord(&manager, amount, time, info,
                                                isPayment);

                recordIDs[recordCount] = id;
                recordCID[recordCount] = 0;
                recordCvaild[recordCount] = expectedCvaild;
                ++recordCount;
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_add_contract(&manager, id, oldID, amount, time, info,
                                   isPayment, expectedCvaild);
            }
            break;
        }
        case 1:
            if (recordCount > 0) {
                size_t index = (size_t)read_u8(&reader) % recordCount;
                int id = recordIDs[index];
                size_t expectedSize = recordCount - 1;

                recordManger_deleteRecordByID(&manager, id);
                check_delete_contract(&manager, id, expectedSize);
                recordIDs[index] = recordIDs[recordCount - 1];
                recordCID[index] = recordCID[recordCount - 1];
                recordCvaild[index] = recordCvaild[recordCount - 1];
                --recordCount;
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        case 2:
            if (recordCount > 0) {
                size_t index = (size_t)read_u8(&reader) % recordCount;
                int id = recordIDs[index];
                const Record *record = record_map_find(&manager.records, id);
                bool wasHidden = record->isHidden;
                char oldPassword[TEXT_LENGTH];
                char password[TEXT_CAPACITY];

                memcpy(oldPassword, record->password, sizeof oldPassword);
                read_text(&reader, password, sizeof password);
                recordManger_hideRecordWithPassword(&manager, id, password);
                check_strings(&manager);
                check_hide_contract(record_map_find(&manager.records, id),
                                    wasHidden, oldPassword, password);
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        case 3: {
            char name[TEXT_CAPACITY];

            read_text(&reader, name, sizeof name);
            if (categoryCount < OBJECT_LIMIT) {
                int cid = recordManger_addCategory(&manager, name);

                categoryIDs[categoryCount] = cid;
                categoryCvaild[categoryCount] = true;
                ++categoryCount;
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        }
        case 4:
            if (categoryCount > 0) {
                size_t index = (size_t)read_u8(&reader) % categoryCount;
                int cid = categoryIDs[index];
                bool existed = category_map_find(&manager.categorys, cid) != NULL;
                bool categoryZeroValid = categoryCvaild[0];
                int moved[OBJECT_LIMIT];
                size_t movedCount = 0;
                size_t recordIndex;

                for (recordIndex = 0; recordIndex < recordCount; ++recordIndex) {
                    if (recordCID[recordIndex] == cid) {
                        moved[movedCount++] = recordIDs[recordIndex];
                        recordCID[recordIndex] = 0;
                        recordCvaild[recordIndex] = categoryZeroValid;
                    }
                }
                recordManger_deleteCategoryByID(&manager, cid);
                if (cid != 0) {
                    categoryIDs[index] = categoryIDs[categoryCount - 1];
                    categoryCvaild[index] = categoryCvaild[categoryCount - 1];
                    --categoryCount;
                }
                check_delete_category_contract(&manager, cid, existed,
                                               categoryZeroValid, moved,
                                               movedCount);
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        case 5:
            if (categoryCount > 0) {
                size_t index = (size_t)read_u8(&reader) % categoryCount;
                int cid = categoryIDs[index];
                bool valid = !categoryCvaild[index];
                size_t recordIndex;

                categoryCvaild[index] = valid;
                for (recordIndex = 0; recordIndex < recordCount; ++recordIndex) {
                    if (recordCID[recordIndex] == cid) {
                        recordCvaild[recordIndex] = valid;
                    }
                }
                recordManger_toggleCategoryVaild(&manager, cid);
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        case 6:
            if (recordCount > 0 && categoryCount > 0) {
                size_t recordIndex = (size_t)read_u8(&reader) % recordCount;
                size_t categoryIndex = (size_t)read_u8(&reader) % categoryCount;

                recordCID[recordIndex] = categoryIDs[categoryIndex];
                recordCvaild[recordIndex] = categoryCvaild[categoryIndex];
                recordManger_setRecordCategory(&manager, recordIDs[recordIndex],
                                               categoryIDs[categoryIndex]);
                check_map_shape(&manager, recordIDs, recordCount, categoryIDs,
                                categoryCount);
                check_strings(&manager);
                check_category_consistency(&manager, recordIDs, recordCID,
                                           recordCvaild, recordCount);
            }
            break;
        case 7: {
            Date start;
            Date end;
            double low;
            double high;

            start.year = read_i32(&reader);
            start.month = read_i32(&reader);
            start.day = read_i32(&reader);
            end.year = read_i32(&reader);
            end.month = read_i32(&reader);
            end.day = read_i32(&reader);
            low = read_double(&reader);
            high = read_double(&reader);
            recordManger_setFilter(&manager, start, end, low, high);
            break;
        }
        default:
            break;
        }
    }

    check_map_shape(&manager, recordIDs, recordCount, categoryIDs, categoryCount);
    check_strings(&manager);
    check_category_consistency(&manager, recordIDs, recordCID, recordCvaild,
                               recordCount);
    check_filter_boundaries();
    check_missing_objects();
    recordManger_free(&manager);
    return 0;
}
