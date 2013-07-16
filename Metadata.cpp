/******************************************************************************
Copyright (c) 2013, Florian Wininger, Etienne Bergeron
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
******************************************************************************/

#include "Metadata.h"

#include <cassert>

namespace etw2ctf {

bool Metadata::Event::operator==(const Event& evt) const {
  if (guid_ != evt.guid_ ||
      opcode_ != evt.opcode_ ||
      version_ != evt.version_ ||
      event_id_ != evt.event_id_ ||
      name_.compare(evt.name_) != 0)
    return false;

  if (fields_.size() != evt.fields_.size())
    return false;
  for (size_t i = 0; i < fields_.size(); ++i)
    if (fields_[i] != evt.fields_[i])
      return false;

  return true;
}

bool Metadata::Field::operator==(const Field& field) const {
  return name_.compare(field.name_) == 0 && type_ == field.type_;
}

size_t Metadata::getEventID(const Event& evt) {
  for (size_t i = 0; i < events_.size(); ++i) {
    if (evt == events_[i])
      return i + 1;
  }
  events_.push_back(evt);
  return events_.size();
}

size_t Metadata::Packet::size() const {
  return buffer_.size();
}

const char* Metadata::Packet::raw_bytes() const {
  if (buffer_.empty())
    return NULL;
  return reinterpret_cast<const char*>(&buffer_[0]);
}

void Metadata::Packet::Reset(size_t size) {
  buffer_.resize(size);
}

void Metadata::Packet::UpdateUInt32(size_t pos, uint32_t value) {
  assert(pos + 3 < buffer_.size());
  buffer_[pos] = static_cast<char>(value);
  buffer_[pos + 1] = static_cast<char>(value >> 8);
  buffer_[pos + 2] = static_cast<char>(value >> 16);
  buffer_[pos + 3] = static_cast<char>(value >> 24);
}

void Metadata::Packet::WriteUInt8(uint8_t value) {
  buffer_.push_back(value);
}

void Metadata::Packet::WriteUInt16(uint16_t value) {
  WriteUInt8(static_cast<uint8_t>(value));
  WriteUInt8(static_cast<uint8_t>(value>>8));
}

void Metadata::Packet::WriteUInt32(uint32_t value) {
  WriteUInt16(static_cast<uint16_t>(value));
  WriteUInt16(static_cast<uint16_t>(value>>16));
}

void Metadata::Packet::WriteUInt64(uint64_t value) {
  WriteUInt32(static_cast<uint32_t>(value));
  WriteUInt32(static_cast<uint32_t>(value>>32));
}

void Metadata::Packet::WriteBytes(const uint8_t* value, size_t len) {
  for (size_t i = 0; i < len; ++i)
    WriteUInt8(value[i]);
}

void Metadata::Packet::WriteString(const std::string& str) {
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(str.c_str());
  WriteBytes(raw, str.length() + 1);  // note: Must add one for '\0'.
}

}  // namespace etw2ctf
