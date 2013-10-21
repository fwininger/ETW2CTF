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
// A dissector is a helper class able to decode a specific kind of payload.
// Dissectors use a self registry mechanism. Do not instantiate a dissector
// with new. Only static instantiation will work safely.
//
// Example:
//  class DummyDissector : public Dissector {
//   public:
//    DummyDissector()
//        : Dissector("Dummy", "Dummy example.") {}
//    bool DecodePayload(...) { ... }
// } dummy; // Performs the auto registry.

#ifndef DISSECTOR_DISSECTORS_H_
#define DISSECTOR_DISSECTORS_H_

#include "converter/metadata.h"

namespace dissector {

// This class is the base class of all dissectors.
class Dissector {
 public:
  // Base constructor of all dissectors. This constructor auto-registers itself
  // and makes the derived class available for payload decoding.
  // @param name name of the dissector.
  // @param descr description of the dissector.
  Dissector(const char* name, const char* descr);

  // Try to decode the given payload with this dissector. This method must be
  // implemented for each dissector.
  // @param guid the provider GUID for the payload.
  // @param opcode the opcode (command) for the payload.
  // @param payload the raw payload to decode.
  // @param length the length of the payload in bytes.
  // @param packet the CTF packet to receive the decoded payload.
  // @param descr the metadata describing the decoded payload.
  // @returns true on success, false on failure.
  virtual bool DecodePayload(const GUID& guid,
                             uint32_t opcode,
                             char* payload,
                             uint32_t length,
                             converter::Metadata::Packet* packet,
                             converter::Metadata::Event* descr) = 0;

  Dissector* next() const { return next_; }

 private:
  // The name of the plugin.
  const char* name_;

  // A human readable description of this dissector.
  const char* descr_;

  // Anchor for a linked list of dissectors.
  Dissector* next_;
};

// Try to decode the given payload with each registered dissector, returning on
// the first one that succeeds. Returns false if no dissectors were successful.
// @param guid the provider GUID for the payload.
// @param opcode the opcode (command) for the payload.
// @param payload the raw payload to decode.
// @param length the length of the payload in bytes.
// @param packet the CTF packet to receive the decoded payload.
// @param descr the metadata describing the decoded payload.
// @returns true on success, false on failure.
bool DecodePayloadWithDissectors(const GUID& guid,
                                 uint32_t opcode,
                                 char* payload,
                                 uint32_t payload_length,
                                 converter::Metadata::Packet* packet,
                                 converter::Metadata::Event* descr);

}  // namespace dissector

#endif  // DISSECTOR_DISSECTORS_H_
