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
// The metadata holds the events layout used to encode CTF streams. Each event
// layout must be assigned to a unique event id.
//
// The metadata keeps a collection of 'Event', and each 'Event' keeps a
// collection of 'Field'. A 'Field' has a name and a type.

#ifndef CONVERTER_METADATA_H_
#define CONVERTER_METADATA_H_

#include <initguid.h>

#include <cstdint>
#include <vector>

namespace converter {

// This class implements a dictionary of event layouts. Each event encoded in
// a CTF stream has a unique event id which correspond to the layout
// description in this dictionary.
class Metadata {
 public:
  // Forward declaration.
  class Event;
  class Field;
  class Packet;

  // Get a unique event id for this event.
  // If the event already exists the function returns the previous id,
  // otherwise it returns a newly created event id.
  // @param event The event whose id we wish to find.
  // @returns a unique event id.
  size_t GetIdForEvent(const Event& event);

  // @returns the number of events in the dictionary.
  size_t size() const { return events_.size(); }

  // Looks up an event by id.
  // @param event_id The id of the event to retrieve.
  // @returns the requested event.
  const Event& GetEventWithId(size_t event_id) const {
    return events_.at(event_id);
  }

 private:
  // Dictionary of event definitions.
  // The event id is the offset in this vector.
  std::vector<Event> events_;
};

// This class contains the information layout for an event.
class Metadata::Event {
 public:
  // Constructor.
  Event() : opcode_(0), version_(0), event_id_(0) {
    ::memset(&guid_, 0, sizeof(GUID));
  }

  // Accessors.
  const std::string& name() const { return name_; }
  void set_name(const std::string& name) { name_ = name; }

  const GUID& guid() const { return guid_; }
  unsigned char opcode() const { return opcode_; }
  unsigned char version() const { return version_; }
  unsigned short event_id() const { return event_id_; }

  // Set the event descriptor information.
  // @guid the guid of this event.
  // @opcode the opcode of this event.
  // @version the version of this event.
  // @event_id the id of this event.
  void set_info(GUID guid, unsigned char opcode, unsigned char version,
                unsigned short event_id) {
    guid_ = guid;
    opcode_ = opcode;
    version_ = version;
    event_id_ = event_id;
  }

  size_t size() const { return fields_.size(); }
  const Field& at(size_t offset) const { return fields_.at(offset); }

  // Compare the event and fields.
  // @param event the event to compare with.
  // @returns true when the event descriptor and layout are the same.
  bool operator==(const Event& event) const;

  // Remove all fields.
  void Reset() { fields_.clear(); }

  // Add a field to the layout. The added field is assumed to have a unique
  // name.
  // @param field the field to add.
  void AddField(const Field& field);

 private:
  // Event identification.
  std::string name_;

  // Event descriptor.
  GUID guid_;
  unsigned char opcode_;
  unsigned char version_;
  unsigned short event_id_;

  // Fields of this event.
  std::vector<Metadata::Field> fields_;
};

// This class describes the layout of a field.
class Metadata::Field {
 public:
  // Type of Field supported.
  enum FieldType {
    INVALID,
    STRUCT_BEGIN,
    STRUCT_END,
    BINARY_FIXED,
    BINARY_VAR,
    INT8,
    INT16,
    INT32,
    INT64,
    UINT8,
    UINT16,
    UINT32,
    UINT64,
    XINT8,
    XINT16,
    XINT32,
    XINT64,
    STRING,
    GUID
  };

  // @name Constructors.
  // @{
  // @param type The type of the encoded layout.
  // @param name The name of the field.
  // @param size The number of elements in an aggregate.
  // @param field_size The name of the field containing the number of elements
  //     in an aggregate type.
  Field() : type_(INVALID), size_(0) {
  }

  Field(FieldType type, const std::string& name)
      : type_(type), name_(name), size_(0) {
  }

  Field(FieldType type, const std::string& name, size_t size)
      : type_(type), name_(name), size_(size) {
  }

  Field(FieldType type, const std::string& name, const std::string& field_size)
      : type_(type), name_(name), size_(0), field_size_(field_size) {
  }
  // @}

  // @name Accessors.
  // @{
  FieldType type() const { return type_; }
  const std::string& name() const { return name_; }
  size_t size() const { return size_; }
  const std::string&  field_size() const { return field_size_; }
  // @}

  // @name Comparators.
  // @{
  bool operator==(const Field& field) const;
  bool operator!=(const Field& field) const {
    return !(*this == field);
  }
  // @}

 private:
  // Field type.
  FieldType type_;

  // Field name.
  std::string name_;

  // The number of elements in aggregate types.
  size_t size_;

  // In case of a variable length array, the field_size contains the name of
  // the field holding the dynamic size.
  std::string field_size_;
};

// This class holds an encoded event with a binary layout described by
// the corresponding description in the Metadata dictionary.
class Metadata::Packet {
 public:
  // @returns a pointer to the raw bytes encoded in this packet.
  const uint8_t* raw_bytes() const;

  // @returns the current size of the encoded packet.
  size_t size() const;

  // Remove every bytes encoded after the offset.
  // @param offset the offset of first byte to remove.
  void Reset(size_t offset);

  // Update an encoded 32-bit value at a given position.
  // @param position the position to update.
  // @param the new value to encode.
  void UpdateUInt32(size_t position, uint32_t value);

  // Encode an 8-bit value.
  // @param value the value to encode.
  void EncodeUInt8(uint8_t value);

  // Encode a 16-bit value.
  // @param value the value to encode.
  void EncodeUInt16(uint16_t value);

  // Encode a 32-bit value.
  // @param value the value to encode.
  void EncodeUInt32(uint32_t value);

  // Encode a 64-bit value.
  // @param value the value to encode.
  void EncodeUInt64(uint64_t value);

  // Encode a sequence of raw bytes.
  // @param value the value to encode.
  // @param length the number of bytes to encode.
  void EncodeBytes(const uint8_t* value, size_t length);

  // Encode a string terminated by zero.
  // @param str the string to encode.
  void EncodeString(const std::string& str);

 private:
  // Internal buffer holding the raw encoded bytes.
  std::vector<uint8_t> buffer_;
};

}  // namespace converter

#endif  // CONVERTER_METADATA_H_
