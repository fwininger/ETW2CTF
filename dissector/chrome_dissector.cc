// Copyright (c) 2013 The ETW2CTF Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//   * Neither the name of the <organization> nor the
//     names of its contributors may be used to endorse or promote products
//     derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Dissector to decode the payload of a Chrome event.
//
// See "doc/Chrome Events.txt" for a complete discussion on Chrome events and
// their representation in the ETW and CTF formats.

#include <cassert>
#include <cstdint>
#include <string>

#include "base/compiler_specific.h"
#include "base/disallow_copy_and_assign.h"
#include "converter/metadata.h"
#include "dissector/dissectors.h"

namespace {

using converter::Metadata;

// Chrome GUID {d2d578d9-2936-45b6-a09f-30e32715f41d}.
const GUID kChromeGuid = {
  0xd2d578d9, 0x2936, 0x45b6, 0xa0, 0x9f, 0x30, 0xe3, 0x27, 0x15, 0xf4, 0x1d };

// Chrome internal event type names, indexed by their ids.
const char* kChromeInternalEventTypeName[] = {
  NULL,  // Not used by Chrome.
  "ChromeBegin",
  "ChromeInstant",
  "ChromeEnd",
  "ChromeFlowBegin",
  "ChromeFlowStep",
  "ChromeFlowEnd",
  "ChromeAsyncBegin",
  "ChromeAsyncStep",
  "ChromeAsyncEnd",
  "ChromeCreateObject",
  "ChromeSnapshotObject",
  "ChromeDeleteObject",
  "ChromeMetadata",
  "ChromeCounter",
  "ChromeSample"
};

// Size of |kChromeInternalEventTypeName|.
const size_t kNumChromeInternalEventTypeName = 16;

// Number of bits to right shift to get a Chrome internal event id from a Chrome
// ETW opcode.
const int kChromeOpcodeInternalEventTypeShift = 4;

// Mask to apply to a Chrome ETW opcode to determine if the event contains a
// stack.
const uint8_t kChromeOpcodeStackMask = 0x08;

// Mask to apply to a Chrome ETW opcode to get the number of arguments.
const uint8_t kChromeOpcodeNumArgsMask = 0x07;

// Name of the fields of a Chrome event.
const char* kChromeNameField = "name";
const char* kChromeIdField = "id";
const char* kChromeCategoriesField = "categories";
const char* kChromeStackSizeField = "stack_size";
const char* kChromeStackField = "stack";
const char* kChromeArgumentsField = "arguments";
const char* kChromeArgumentNameField = "arg_name";
const char* kChromeArgumentValueField = "arg_value";

// Decodes the payload of a Chrome event.
class ChromeDissector : public dissector::Dissector {
 public:
  ChromeDissector()
      : Dissector("Chrome", "Decode Chrome EVENT_TRACE payload.") {
  }

  // Overrides dissector::Dissector.
  bool DecodePayload(const GUID& guid,
                     uint8_t opcode,
                     char* payload,
                     uint32_t length,
                     Metadata::Packet* packet,
                     Metadata::Event* descr) OVERRIDE;

 private:
  DISALLOW_COPY_AND_ASSIGN(ChromeDissector);
} chrome;

bool ChromeDissector::DecodePayload(const GUID& guid,
                                    uint8_t opcode,
                                    char* payload,
                                    uint32_t length,
                                    Metadata::Packet* packet,
                                    Metadata::Event* descr) {
  if (!IsEqualGUID(guid, kChromeGuid))
    return false;

  assert(payload != NULL);
  assert(packet != NULL);
  assert(descr != NULL);

  // Retrieve the event type name.
  size_t internal_event_id = opcode >> kChromeOpcodeInternalEventTypeShift;
  if (internal_event_id >= kNumChromeInternalEventTypeName)
    return false;
  const char* event_type_name = kChromeInternalEventTypeName[internal_event_id];
  if (event_type_name == NULL)
    return false;
  descr->set_name(event_type_name);
  // TODO(fdoray): Insert the right version and event id.
  descr->set_info(guid, opcode, 0, 0);

  // Decode the payload.
  uint32_t offset = 0;

  // Decode the event name.
  if (offset + 1 > length)
    return false;
  std::string event_name(&payload[offset], 0, length - offset - 1);
  offset += event_name.size() + 1;

  descr->AddField(Metadata::Field(Metadata::Field::STRING, kChromeNameField));
  packet->EncodeString(event_name);

  // Decode the event id.
  if (offset + sizeof(uint64_t) > length)
    return false;
  uint64_t event_id = *reinterpret_cast<uint64_t*>(&payload[offset]);
  offset += sizeof(uint64_t);

  descr->AddField(Metadata::Field(Metadata::Field::XINT64, kChromeIdField));
  packet->EncodeUInt64(event_id);

  // Decode the categories.
  if (offset + 1 > length)
    return false;
  std::string event_categories(&payload[offset], 0, length - offset - 1);
  offset += event_categories.size() + 1;

  descr->AddField(Metadata::Field(Metadata::Field::STRING,
                                  kChromeCategoriesField));
  packet->EncodeString(event_categories);

  // Decode the arguments.
  int num_args = opcode & kChromeOpcodeNumArgsMask;
  if (num_args > 0) {
    // Describe the fields associated with arguments. 
    size_t args_array_scope = descr->size();

    descr->AddField(Metadata::Field(Metadata::Field::ARRAY_FIXED,
                                    kChromeArgumentsField,
                                    num_args, Metadata::kRootScope));
    size_t args_struct_scope = descr->size();
    descr->AddField(Metadata::Field(Metadata::Field::STRUCT_BEGIN,
                                    kChromeArgumentsField,
                                    args_array_scope));
    descr->AddField(Metadata::Field(Metadata::Field::STRING,
                                    kChromeArgumentNameField,
                                    args_struct_scope));
    descr->AddField(Metadata::Field(Metadata::Field::STRING,
                                    kChromeArgumentValueField,
                                    args_struct_scope));
    descr->AddField(Metadata::Field(Metadata::Field::STRUCT_END,
                                    "", args_array_scope));

    for (int i = 0; i < num_args; ++i) {
      // Decode the argument name.
      if (offset + 1 > length)
        return false;
      std::string argument_name(&payload[offset], 0, length - offset - 1);
      offset += argument_name.size() + 1;
      packet->EncodeString(argument_name);

      // Decode the argument value.
      if (offset + 1 > length)
        return false;
      std::string argument_value(&payload[offset], 0, length - offset - 1);
      offset += argument_value.size() + 1;
      packet->EncodeString(argument_value);
    }
  }

  if (opcode & kChromeOpcodeStackMask) {
    // Stack size.
    if (offset + sizeof(uint32_t) > length)
      return false;
    uint32_t stack_size = *reinterpret_cast<uint32_t*>(&payload[offset]);
    offset += sizeof(uint32_t);

    descr->AddField(Metadata::Field(Metadata::Field::UINT32,
                                    kChromeStackSizeField));
    packet->EncodeUInt32(stack_size);

    // Stack pointers.
    size_t stack_pointers_parent = descr->size();
    descr->AddField(Metadata::Field(Metadata::Field::ARRAY_VAR,
                                    kChromeStackField, kChromeStackSizeField,
                                    Metadata::kRootScope));
    descr->AddField(Metadata::Field(Metadata::Field::XINT32, kChromeStackField,
                                    stack_pointers_parent));

    size_t stack_size_bytes = stack_size * sizeof(uint32_t);
    if (offset + stack_size_bytes > length)
      return false;
    packet->EncodeBytes(reinterpret_cast<uint8_t*>(&payload[offset]),
                        stack_size_bytes);

    offset += stack_size_bytes;
  }

  // Check whether some data has not been decoded.
  if (offset != length)
    return false;

  return true;
}

}  // namespace
