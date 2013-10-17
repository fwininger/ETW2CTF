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

#include "converter/metadata.h"

#include <cassert>
#include <string>

namespace converter {

bool Metadata::Event::operator==(const Event& event) const {
  if (guid_ != event.guid_ ||
      opcode_ != event.opcode_ ||
      version_ != event.version_ ||
      event_id_ != event.event_id_ ||
      name_.compare(event.name_) != 0) {
    return false;
  }

  if (fields_.size() != event.fields_.size())
    return false;
  for (size_t i = 0; i < fields_.size(); ++i) {
    if (fields_[i] != event.fields_[i])
      return false;
  }

  return true;
}

bool Metadata::Field::operator==(const Field& field) const {
  return type_ == field.type_ &&
      size_ == field.size_ &&
      parent_ == field.parent_ &&
      name_.compare(field.name_) == 0 &&
      field_size_.compare(field.field_size_) == 0;
}

size_t Metadata::GetIdForEvent(const Event& event) {
  for (size_t i = 0; i < events_.size(); ++i) {
    if (event == events_[i])
      return i + 1;
  }
  events_.push_back(event);
  return events_.size();
}

void Metadata::Event::AddField(const Field& field) {
  for (size_t i = 0; i < fields_.size(); ++i) {
    // Avoid same field name in a scope.
    if (field.parent() == fields_[i].parent()) {
      assert(fields_[i].name() != field.name());
    }
  }
  fields_.push_back(field);
}

uint64_t Metadata::Packet::timestamp() const {
  return timestamp_;
}

void Metadata::Packet::set_timestamp(uint64_t time) {
  timestamp_ = time;
}

size_t Metadata::Packet::size() const {
  return buffer_.size();
}

const uint8_t* Metadata::Packet::raw_bytes() const {
  if (buffer_.empty())
    return NULL;
  return reinterpret_cast<const uint8_t*>(&buffer_[0]);
}

void Metadata::Packet::Reset(size_t offset) {
  buffer_.resize(offset);
}

void Metadata::Packet::UpdateUInt32(size_t offset, uint32_t value) {
  assert(offset + 3 < buffer_.size());
  buffer_[offset] = static_cast<char>(value);
  buffer_[offset + 1] = static_cast<char>(value >> 8);
  buffer_[offset + 2] = static_cast<char>(value >> 16);
  buffer_[offset + 3] = static_cast<char>(value >> 24);
}

void Metadata::Packet::UpdateUInt64(size_t offset, uint64_t value) {
  UpdateUInt32(offset, static_cast<uint32_t>(value));
  UpdateUInt32(offset + 4, static_cast<uint32_t>(value >> 32));
}

void Metadata::Packet::EncodeUInt8(uint8_t value) {
  buffer_.push_back(value);
}

void Metadata::Packet::EncodeUInt16(uint16_t value) {
  EncodeUInt8(static_cast<uint8_t>(value));
  EncodeUInt8(static_cast<uint8_t>(value >> 8));
}

void Metadata::Packet::EncodeUInt32(uint32_t value) {
  EncodeUInt16(static_cast<uint16_t>(value));
  EncodeUInt16(static_cast<uint16_t>(value >> 16));
}

void Metadata::Packet::EncodeUInt64(uint64_t value) {
  EncodeUInt32(static_cast<uint32_t>(value));
  EncodeUInt32(static_cast<uint32_t>(value >> 32));
}

void Metadata::Packet::EncodeBytes(const uint8_t* value, size_t length) {
  for (size_t i = 0; i < length; ++i)
    EncodeUInt8(value[i]);
}

void Metadata::Packet::EncodeString(const std::string& str) {
  const uint8_t* raw = reinterpret_cast<const uint8_t*>(str.c_str());
  // The length must take into account the terminal '\0'.
  EncodeBytes(raw, str.length() + 1);
}

}  // namespace converter
