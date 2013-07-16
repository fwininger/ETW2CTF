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
#ifndef CTF2ETW_METADATA_H
#define CTF2ETW_METADATA_H

#include <initguid.h>

#include <cstdint>
#include <vector>

namespace etw2ctf {

class Metadata {
 public:
   // Forward declaration.
   class Event;
   class Field;
   class Packet;

 public :
  // Get a unique event id for this event.
  // If the event already exists, the function return the previous ID,
  // otherwise it returns a newly created ID.
  size_t getEventID(const Event& evt);

  size_t size() const { return events_.size(); }
  const Event& at(size_t offset) const { return events_[offset]; }

 private:
  // Event definitions.
  std::vector<Event> events_;
};

class Metadata::Event {
 public:
  // Constructor
  Event() :
    opcode_(0), version_(0), event_id_(0) {
  }

  // Accessors.
  const std::string& name() const { return name_; }
  void set_name(const std::string& name) { name_ = name; }

  void set_info(GUID guid, unsigned char opcode, unsigned char version,
      unsigned short event_id) {
    guid_ = guid;
    opcode_ = opcode;
    version_ = version;
    event_id_ = event_id;
  }

  size_t size() const { return fields_.size(); }
  const Field& at(size_t offset) const { return fields_[offset]; }

  bool operator==(const Event& evt) const;

  void Reset() { fields_.clear(); }
  void AddField(const Field& field) { fields_.push_back(field); }

private:
  // Event identification
  std::string name_;
  GUID guid_;
  unsigned char opcode_;
  unsigned char version_;
  unsigned short event_id_;

  // List of Field.
  std::vector<Metadata::Field> fields_;
};

class Metadata::Field {
public:
  // Type of Field supported.
  enum FIELDTYPE {
    INVALID,
    STRUCT_BEGIN, STRUCT_END,
    BINARY_FIXED, BINARY_VAR,
    BIT, BIT5, BIT7, BIT13,
    INT8, INT16, INT32, INT64,
    UINT8, UINT16, UINT32, UINT64,
    XINT8, XINT16, XINT32, XINT64,
    STRING, GUID
  };

  Field() : type_(INVALID), size_(0) {
  }

  Field(FIELDTYPE type, const std::string& name)
    : type_(type), name_(name), size_(0) {
  }

  Field(FIELDTYPE type, const std::string& name, size_t size)
    : type_(type), name_(name), size_(size) {
  }

  Field(FIELDTYPE type, const std::string& name, const std::string& field_size)
    : type_(type), name_(name), size_(0), field_size_(field_size) {
  }

  // Accessors.
  FIELDTYPE type() const { return type_; }
  const std::string& name() const { return name_; }
  size_t size() const { return size_; }
  const std::string&  field_size() const { return field_size_; }

  // Comparator.
  bool operator==(const Field& field) const;
  bool operator!=(const Field& field) const {
    return !(*this == field);
  }

private:
  // Field Type.
  FIELDTYPE type_;

  // Field Name.
  std::string name_;
  size_t size_;
  std::string field_size_;
};

class Metadata::Packet {
public:
  Packet() {
  }

  size_t size() const;
  const char* raw_bytes() const;
  void Reset(size_t size);

  void UpdateUInt32(size_t position, uint32_t value);

  void WriteUInt8(uint8_t value);
  void WriteUInt16(uint16_t value);
  void WriteUInt32(uint32_t value);
  void WriteUInt64(uint64_t value);
  void WriteBytes(const uint8_t* value, size_t len);

  void WriteString(const std::string& str);

 private:
  std::vector<uint8_t> buffer_;
};

}  // namespace etw2ctf

#endif
