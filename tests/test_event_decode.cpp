// cppcheck-suppress-file missingIncludeSystem
/*
 * Regression tests for the production ring-buffer event consumer `handle_event`
 * (src/events.cpp), focused on the forensic-event decode.
 *
 * Forensic events are emitted by the BPF side as a *bare* `forensic_event` (its
 * own `type` at offset 0, sizeof == 104), reserved directly on the ring buffer —
 * NOT wrapped in the `Event` union. An earlier `handle_event` decoded them
 * through a stale `Event::forensic` union member at offset 8, which both shifted
 * every field by 8 bytes AND read 8 bytes past the 104-byte record. These tests
 * pin the corrected offset-0 decode:
 *
 *   * field correctness — pid/ppid/comm/action read from the bare record;
 *   * no over-read — the record is allocated tightly at exactly sizeof, so the
 *     ASan/UBSan CI builds turn any over-read past the 104th byte into a hard
 *     failure (the regression guard for the byte-range bug specifically).
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "events.hpp"
#include "types.hpp"

namespace {

// Build a bare forensic_event record (exactly sizeof(ForensicEvent) bytes, no
// slack) with the given identifying fields.
std::vector<uint8_t> make_bare_forensic(uint32_t pid, uint32_t ppid, uint32_t uid, const std::string& comm,
                                        const std::string& action)
{
    std::vector<uint8_t> buf(sizeof(aegis::ForensicEvent), 0);
    const uint32_t type = aegis::EVENT_FORENSIC_BLOCK;
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, type), &type, sizeof(type));
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, pid), &pid, sizeof(pid));
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, ppid), &ppid, sizeof(ppid));
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, uid), &uid, sizeof(uid));
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, comm), comm.data(),
                std::min(comm.size(), sizeof(aegis::ForensicEvent::comm) - 1));
    std::memcpy(buf.data() + offsetof(aegis::ForensicEvent, action), action.data(),
                std::min(action.size(), sizeof(aegis::ForensicEvent::action) - 1));
    return buf;
}

// Capture stdout produced by `handle_event` (the Aegis-native JSON sink).
std::string capture_handle_event(std::vector<uint8_t>& record)
{
    std::ostringstream sink;
    std::streambuf* old = std::cout.rdbuf(sink.rdbuf());
    aegis::handle_event(nullptr, record.data(), record.size());
    std::cout.rdbuf(old);
    return sink.str();
}

} // namespace

TEST(EventDecode, ForensicBareRecordDecodesAtOffsetZero)
{
    // uid chosen unlikely-to-resolve so no host-dependent "username" field appears.
    auto record = make_bare_forensic(/*pid=*/4242, /*ppid=*/778, /*uid=*/4000001, /*comm=*/"sshd", /*action=*/"DENY");
    const std::string out = capture_handle_event(record);

    EXPECT_NE(out.find("\"type\":\"forensic_block\""), std::string::npos) << out;
    EXPECT_NE(out.find("\"pid\":4242"), std::string::npos) << out;
    EXPECT_NE(out.find("\"ppid\":778"), std::string::npos) << out;
    EXPECT_NE(out.find("\"uid\":4000001"), std::string::npos) << out;
    EXPECT_NE(out.find("\"comm\":\"sshd\""), std::string::npos) << out;
    EXPECT_NE(out.find("\"action\":\"DENY\""), std::string::npos) << out;

    // The old offset-8 decode would have surfaced ppid (778) as "pid" and shifted
    // comm/action into garbage — these would then be absent.
    EXPECT_EQ(out.find("\"pid\":778"), std::string::npos) << "field-shift regression: " << out;
}

TEST(EventDecode, ForensicBareRecordNoOverRead)
{
    // The record is allocated at exactly sizeof(ForensicEvent) with no trailing
    // slack; under ASan/UBSan an 8-byte over-read past the 104th byte (the old
    // bug) faults here. With the offset-0 decode the read fits exactly.
    auto record = make_bare_forensic(1, 2, 3, "x", "AUDIT");
    ASSERT_EQ(record.size(), sizeof(aegis::ForensicEvent));
    (void)capture_handle_event(record); // must not over-read
}
