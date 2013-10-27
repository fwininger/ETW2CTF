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

#include "dissector/dissectors.h"

#include <cassert>

namespace dissector {
namespace {

// CHROME GUID {b967ae67-bb22-49d7-9406-55d91ee1d560}.
const GUID kChromeGuid = { 0xB967AE67, 0xBB22, 0x49D7,
  { 0x94, 0x06, 0x55, 0xD9, 0x1E, 0xE1, 0xD5, 0x60 }};

class ChromeDissector : public Dissector {
 public:
  ChromeDissector()
      : Dissector("Chrome", "Decode Chrome EVENT_TRACE payload.") {
  }

  bool DecodePayload(const GUID& guid,
                     uint32_t opcode,
                     char* payload,
                     uint32_t length,
                     converter::Metadata::Packet* packet,
                     converter::Metadata::Event* descr);
} chrome;

bool ChromeDissector::DecodePayload(const GUID& guid,
                                    uint32_t opcode,
                                    char* payload,
                                    uint32_t length,
                                    converter::Metadata::Packet* packet,
                                    converter::Metadata::Event* descr) {
  if (!IsEqualGUID(guid, kChromeGuid))
    return false;

  assert(packet != NULL);
  assert(descr != NULL);

  // TODO(etienneb): Implement this function.
  return false;
}

}  // namespace
}  // namespace dissector
