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

#include "converter/etw_consumer.h"

#include <cassert>
#include <iostream>
#include <sstream>

#include "dissector/dissectors.h"
#include "etw_observer/etw_observer.h"

namespace converter {

namespace {

const size_t kRootScope = static_cast<size_t>(-1);

// Specify to CTF consumer that source come from ETW.
// ETW2CTF GUID {29cb3580-13c6-4c85-a4cb-a2c0ffa68890}.
const GUID ETWConverterGuid = { 0x29CB3580, 0x13C6, 0x4C85,
    { 0xA4, 0xCB, 0xA2, 0xC0, 0xFF, 0xA6, 0x88, 0x90 }};

//  Convert a GUID to a string representation.
std::string GuidToString(const GUID& guid) {
  const int kMAX_GUID_STRING_LENGTH = 38;
  char buffer[kMAX_GUID_STRING_LENGTH];
  sprintf_s(buffer, kMAX_GUID_STRING_LENGTH,
      "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
      guid.Data1,
      guid.Data2,
      guid.Data3,
      guid.Data4[0],
      guid.Data4[1],
      guid.Data4[2],
      guid.Data4[3],
      guid.Data4[4],
      guid.Data4[5],
      guid.Data4[6],
      guid.Data4[7]);
  return std::string(buffer);
}

std::string ConvertString(const wchar_t* pstr) {
  assert(pstr != NULL);
  std::wstring wstr(pstr);
  return std::string(wstr.begin(), wstr.end());
}

void EncodeGUID(const GUID& guid, Metadata::Packet* packet) {
  assert(packet != NULL);
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 24));
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 16));
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data1 >> 8));
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data1));

  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data2 >> 8));
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data2));

  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data3 >> 8));
  packet->EncodeUInt8(static_cast<uint8_t>(guid.Data3));

  packet->EncodeBytes(guid.Data4, 8);
}

}  // namespace

bool ETWConsumer::GetBufferName(PEVENT_TRACE_LOGFILEW ptrace,
                                std::wstring* name) const {
  assert(name != NULL);

  if (!ptrace)
    return false;

  std::wstringstream ss;
  ss << L"stream" << ptrace->BuffersRead;

  *name = ss.str();
  return true;
}

bool ETWConsumer::ConsumeAllEvents() {
  // Open all trace files, and keep handles in a vector.
  std::vector<TRACEHANDLE> handles;
  for (size_t i = 0; i < traces_.size(); ++i) {
    EVENT_TRACE_LOGFILE trace;
    ::memset(&trace, 0, sizeof(trace));
    trace.LogFileName = const_cast<LPWSTR>(traces_[i].c_str());
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.BufferCallback = buffer_callback_;
    trace.EventRecordCallback = event_callback_;

    TRACEHANDLE th = ::OpenTrace(&trace);
    if (th == INVALID_PROCESSTRACE_HANDLE) {
      DWORD error = ::GetLastError();
      std::wcerr << L"OpenTrace failed with error " << error << std::endl;
      return false;
    }

    handles.push_back(th);
  }

  // If no trace files, leave with an error.
  if (handles.empty())
    return false;

  // Reserve some memory space for internal buffers.
  data_property_buffer_.resize(1024);
  packet_info_buffer_.resize(64*1024);

  // Ask the ETW API to consume all traces and calls the registered callbacks.
  bool valid = true;
  ULONG status = ::ProcessTrace(&handles[0], 1, 0, 0);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"ProcessTrace failed with error " << status << std::endl;
    valid = false;
  }

  // Close all trace files.
  for (size_t i = 0; i < handles.size(); ++i)
    ::CloseTrace(handles[i]);

  // Free unused memory.
  data_property_buffer_.clear();
  packet_info_buffer_.clear();

  return valid;
}

bool ETWConsumer::IsFullPacketReady() {
  if (packets_.empty())
    return false;
  return packet_total_bytes_ >= packet_maximal_size_;
}

bool ETWConsumer::IsSendingQueueEmpty() {
  return packet_total_bytes_ == 0;
}

void ETWConsumer::AddPacketToSendingQueue(const Metadata::Packet& packet) {
  assert(packet.size() > 0);
  packet_total_bytes_ += packet.size();
  packets_.push_back(packet);
}

void ETWConsumer::PopPacketFromSendingQueue() {
  assert(!packets_.empty());
  packet_total_bytes_ -= packets_.front().size();
  packets_.pop_front();
}

void ETWConsumer::BuildFullPacket(Metadata::Packet* output) {
  assert(output != NULL);
  assert(packet_total_bytes_ != 0);

  // Encode and Write stream header.
  size_t packet_context_offset = 0;
  EncodePacketHeader(output, &packet_context_offset);
  assert(packet_context_offset != 0);

  unsigned int packet_count = 0;
  uint64_t start_timestamp = UINT64_MAX;
  uint64_t stop_timestamp = 0;

  while (packet_total_bytes_ > 0) {
    const Metadata::Packet& packet = packets_.front();
    // Always encode the first packet: the payload of the first packet may be
    // bigger than the maximal packet size.
    if (packet_count != 0) {
      // Stop appending packet when maximal size is reached.
      if (output->size() + packet.size() > packet_maximal_size_)
        break;
    }

    // Keep track of timestamps.
    uint64_t timestamp = packet.timestamp();
    start_timestamp = std::min<uint64_t>(start_timestamp, timestamp);
    stop_timestamp = std::max<uint64_t>(stop_timestamp, timestamp);

    // Append this packet payload to the output packet.
    output->EncodeBytes(packet.raw_bytes(), packet.size());
    packet_count++;
    PopPacketFromSendingQueue();
  }

  // Get packet content size.
  uint32_t content_size = output->size();

  // Add padding.
  if (packet_maximal_size_ != 0) {
    while ((output->size() % packet_maximal_size_) != 0)
      output->EncodeUInt8(0);
  }

  // Get packet size (payload + padding).
  uint32_t packet_size = output->size();

  // Update the output packet header.
  UpdatePacketHeader(packet_context_offset, content_size, packet_size,
                     start_timestamp, stop_timestamp, output);
}

void ETWConsumer::EncodePacketHeader(Metadata::Packet* packet,
                                     size_t* packet_context_offset) {
  assert(packet != NULL);
  assert(packet_context_offset != NULL);

  const uint32_t kCtfMagicNumber = 0xC1FC1FC1;

  // Output trace.header.magic.
  packet->EncodeUInt32(kCtfMagicNumber);

  // Output trace.header.uuid.
  EncodeGUID(ETWConverterGuid, packet);

  // Returns the offset where context values will be updated.
  *packet_context_offset = packet->size();

  // Output trace.header.content_size.
  packet->EncodeUInt32(0);
  // Output trace.header.packet_size.
  packet->EncodeUInt32(0);

  // Output trace.header.start/stop_timestamp.
  packet->EncodeUInt64(0);
  packet->EncodeUInt64(0);
}

void ETWConsumer::UpdatePacketHeader(size_t packet_context_offset,
                                     uint32_t content_size,
                                     uint32_t packet_size,
                                     uint64_t start_timestamp,
                                     uint64_t stop_timestamp,
                                     Metadata::Packet* packet) {
  assert(packet != NULL);

  // content_size is encoded in bits.
  packet->UpdateUInt32(packet_context_offset, content_size * 8);
  packet_context_offset += 4;

  // packet_size is encoded in bits.
  packet->UpdateUInt32(packet_context_offset, packet_size * 8);
  packet_context_offset += 4;

  // Start timestamp.
  packet->UpdateUInt64(packet_context_offset, start_timestamp);
  packet_context_offset += 8;

  // Stop timestamp.
  packet->UpdateUInt64(packet_context_offset, stop_timestamp);
  packet_context_offset += 8;
}

bool ETWConsumer::ProcessBuffer(PEVENT_TRACE_LOGFILEW ptrace) {
  assert(ptrace != NULL);
  return true;
}

bool ETWConsumer::ProcessEvent(PEVENT_RECORD pevent) {
  FOR_EACH_ETW_OBSERVER(OnBeginProcessEvent(this, pevent));
  bool res = ProcessEventInternal(pevent);
  FOR_EACH_ETW_OBSERVER(OnEndProcessEvent(this, pevent));
  return res;
}

bool ETWConsumer::ProcessEventInternal(PEVENT_RECORD pevent) {
  assert(pevent != NULL);

  // Skip tracing events.
  if (IsEqualGUID(pevent->EventHeader.ProviderId, EventTraceGuid) &&
      pevent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
    return false;
  }

  Metadata::Packet packet;

  // Output stream.header.timestamp.
  uint64_t timestamp = pevent->EventHeader.TimeStamp.QuadPart;
  packet.set_timestamp(timestamp);
  packet.EncodeUInt64(timestamp);

  // Output stream.header.id, and keep track of the current position to update
  // it later when the payload is fully decoded and can be bound to a valid
  // unique event id.
  size_t event_id = 0;
  size_t event_id_position = packet.size();
  packet.EncodeUInt32(event_id);

  // Output stream.context.ev_*.
  packet.EncodeUInt16(pevent->EventHeader.EventDescriptor.Id);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Version);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Channel);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Level);
  packet.EncodeUInt8(pevent->EventHeader.EventDescriptor.Opcode);
  packet.EncodeUInt16(pevent->EventHeader.EventDescriptor.Task);
  packet.EncodeUInt64(pevent->EventHeader.EventDescriptor.Keyword);

  // Output stream.context.pid/tid/cpu_id.
  packet.EncodeUInt32(pevent->EventHeader.ProcessId);
  packet.EncodeUInt32(pevent->EventHeader.ThreadId);
  packet.EncodeUInt8(pevent->BufferContext.ProcessorNumber);
  packet.EncodeUInt16(pevent->BufferContext.LoggerId);

  // Output stream.context.uuid.
  EncodeGUID(pevent->EventHeader.ProviderId, &packet);
  EncodeGUID(pevent->EventHeader.ActivityId, &packet);

  // Output stream.context.header_type.
  packet.EncodeUInt16(pevent->EventHeader.HeaderType);

  // Output stream.context.header_flags.
  packet.EncodeUInt16(pevent->EventHeader.Flags);
  packet.EncodeUInt16(pevent->EventHeader.Flags);

  // Output stream.context.header_properties.
  packet.EncodeUInt16(pevent->EventHeader.EventProperty);
  packet.EncodeUInt16(pevent->EventHeader.EventProperty);

  // Output cpu_id.
  packet.EncodeUInt8(pevent->BufferContext.ProcessorNumber);

  // Decode the packet payload.
  Metadata::Event descr;
  size_t payload_position = packet.size();

  if (!DecodePayload(pevent, &packet, &descr)) {
    // On failure, remove packet data and metadata.
    descr.Reset();
    packet.Reset(payload_position);

    // Try to decode the payload using a dissector.
    const GUID& guid = pevent->EventHeader.ProviderId;
    uint32_t opcode = pevent->EventHeader.EventDescriptor.Opcode;
    char* data = static_cast<char*>(pevent->UserData);
    uint32_t length = pevent->UserDataLength;
    bool decoded = dissector::DecodePayloadWithDissectors(guid, opcode, data,
                                                          length, &packet,
                                                          &descr);
    if (!decoded) {
      // Send the raw payload.
      if (!SendRawPayload(pevent, &packet, &descr))
        return false;
    }
  }

  // Update the event_id, now we have the full layout information.
  event_id = metadata_.GetIdForEvent(descr);
  packet.UpdateUInt32(event_id_position, event_id);

  // Add this packet to the sending queue.
  AddPacketToSendingQueue(packet);

  return true;
}

bool ETWConsumer::SendRawPayload(PEVENT_RECORD pevent,
                                 Metadata::Packet* packet,
                                 Metadata::Event* descr) {
  assert(pevent != NULL);
  assert(packet != NULL);
  assert(descr != NULL);

  // Get raw data pointer and size.
  USHORT length = pevent->UserDataLength;
  PVOID data = pevent->UserData;
  const size_t parent = kRootScope;

  // Create the metadata fields.
  typedef Metadata::Field Field;
  Metadata::Field field_size(Field::UINT16, "size", parent);
  Metadata::Field field_data(Field::BINARY_VAR, "data", "size", parent);
  descr->AddField(field_size);
  descr->AddField(field_data);

  // Encode the length and the payload.
  packet->EncodeUInt16(length);
  packet->EncodeBytes(static_cast<uint8_t*>(data), length);

  return true;
}

bool ETWConsumer::DecodePayload(
     PEVENT_RECORD pevent, Metadata::Packet* packet, Metadata::Event* descr) {
  assert(pevent != NULL);
  assert(packet != NULL);
  assert(descr != NULL);

  // Assume initial scope is the root scope.
  const size_t parent = kRootScope;

  // If the EVENT_HEADER_FLAG_STRING_ONLY flag is set, the event data is a
  // null-terminated string. Those events are generated via EventWriteString
  // function.
  if ((pevent->EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0) {
    // Encode string data.
    LPWSTR wptr = static_cast<LPWSTR>(pevent->UserData);
    std::string str = ConvertString(wptr);
    packet->EncodeString(str);

    // Create the metadata fields.
    Metadata::Field field_data(Metadata::Field::STRING, "data", parent);
    descr->AddField(field_data);
    return true;
  }

  // Decode the metadata via trace data helper (TDH) using
  // TdhGetEventInformation.
  DWORD buffer_size = packet_info_buffer_.size();
  ::memset(&packet_info_buffer_[0], 0, buffer_size);
  PTRACE_EVENT_INFO pinfo =
      reinterpret_cast<PTRACE_EVENT_INFO>(&packet_info_buffer_[0]);

  DWORD status = TdhGetEventInformation(pevent, 0, NULL, pinfo, &buffer_size);
  if (status == ERROR_INSUFFICIENT_BUFFER) {
    // The internal buffer is too small, resize it and try again.
    packet_info_buffer_.resize(buffer_size);
    pinfo = reinterpret_cast<PTRACE_EVENT_INFO>(&packet_info_buffer_[0]);
    status = TdhGetEventInformation(pevent, 0, NULL, pinfo, &buffer_size);
  }

  if (status != ERROR_SUCCESS)
    return false;

  // Notify the observers that the event information has been extracted.
  FOR_EACH_ETW_OBSERVER(OnExtractEventInfo(this, pevent, pinfo));

  // Filter the decoding source we don't know how to handle.
  if (pinfo->DecodingSource != DecodingSourceWbem &&
      pinfo->DecodingSource != DecodingSourceXMLFile) {
    return false;
  }

  // Retrieve event descriptor information.
  descr->set_info(pinfo->EventGuid,
                  pevent->EventHeader.EventDescriptor.Opcode,
                  pevent->EventHeader.EventDescriptor.Version,
                  pevent->EventHeader.EventDescriptor.Id);

  // Retrieve event opcode name.
  if (pinfo->OpcodeNameOffset > 0) {
    size_t name_offset = pinfo->OpcodeNameOffset;
    LPWSTR opcode_ptr =
        reinterpret_cast<LPWSTR>(&packet_info_buffer_[name_offset]);
    std::string opcode_name = ConvertString(opcode_ptr);
    descr->set_name(opcode_name);
  }

  // Decode each field.
  for (size_t i = 0; i < pinfo->TopLevelPropertyCount; ++i) {
    size_t packet_offset = packet->size();
    size_t descr_offset = descr->size();
    if (!DecodePayloadField(pevent, pinfo, parent, i, packet, descr)) {
      // Reset state.
      packet->Reset(packet_offset);
      descr->Reset(descr_offset);
      // Send this field in raw.
      if (!SendRawPayloadField(pevent, pinfo, parent, i, packet, descr)) {
        // Reset state.
        packet->Reset(packet_offset);
        descr->Reset(descr_offset);
        return false;
      }
    }
  }

  return true;
}

bool ETWConsumer::SendRawPayloadField(PEVENT_RECORD pevent,
                                      PTRACE_EVENT_INFO pinfo,
                                      size_t parent,
                                      unsigned int field_index,
                                      Metadata::Packet* packet,
                                      Metadata::Event* descr) const {
  assert(pevent != NULL);
  assert(pinfo != NULL);
  assert(packet != NULL);
  assert(descr != NULL);

  // Retrieve the field to decode.
  const EVENT_PROPERTY_INFO& field =
      pinfo->EventPropertyInfoArray[field_index];

  // Field length.
  size_t length = pinfo->EventPropertyInfoArray[field_index].length;

  // Determine the offset
  size_t offset = 0;
  for (size_t i = 0; i < field_index; ++i)
    offset += pinfo->EventPropertyInfoArray[i].length;

  if (offset + length > pevent->UserDataLength)
    return false;

  // Retrieve data.
  PBYTE raw_data = static_cast<PBYTE>(pevent->UserData);
  uint8_t* data = static_cast<uint8_t*>(&raw_data[offset]);

  // Keep a raw byte pointer to ease indirection through pinfo.
  PBYTE raw_info = reinterpret_cast<PBYTE>(pinfo);

  // Retrieve field name.
  assert(field.NameOffset != 0);
  size_t name_offset = field.NameOffset;
  LPWSTR name_ptr = reinterpret_cast<LPWSTR>(&raw_info[name_offset]);
  std::string field_name = ConvertString(name_ptr);

  // Create a scope for the structure.
  unsigned int scope = descr->size();
  descr->AddField(
      Metadata::Field(Metadata::Field::STRUCT_BEGIN, field_name, parent));

  // Create the metadata fields.
  descr->AddField(
      Metadata::Field(Metadata::Field::UINT16, "size", scope));
  descr->AddField(
      Metadata::Field(Metadata::Field::BINARY_VAR, "data", "size", scope));

  // Close the scope.
  descr->AddField(Metadata::Field(Metadata::Field::STRUCT_END, "", scope));

  // Encode the length and the payload.
  packet->EncodeUInt16(length);
  packet->EncodeBytes(data, length);

  return true;
}

bool ETWConsumer::DecodePayloadField(PEVENT_RECORD pevent,
                                     PTRACE_EVENT_INFO pinfo,
                                     size_t parent,
                                     unsigned int field_index,
                                     Metadata::Packet* packet,
                                     Metadata::Event* descr) {
  assert(pevent != NULL);
  assert(pinfo != NULL);
  assert(packet != NULL);
  assert(descr != NULL);

  // Retrieve the field to decode.
  const EVENT_PROPERTY_INFO& field =
      pinfo->EventPropertyInfoArray[field_index];

  // Retrieve field information.
  size_t count = pinfo->EventPropertyInfoArray[field_index].count;
  size_t flags = pinfo->EventPropertyInfoArray[field_index].Flags;

  // Keep a raw byte pointer to ease indirection through pinfo.
  PBYTE raw_info = (PBYTE)pinfo;

  // Retrieve field name.
  assert(field.NameOffset != 0);
  size_t name_offset = field.NameOffset;
  LPWSTR name_ptr = reinterpret_cast<LPWSTR>(&raw_info[name_offset]);
  std::string field_name = ConvertString(name_ptr);

  // Contains the field information.
  Metadata::Field merged_field;

  // TODO(bergeret): Handle aggregate types (struct, ...).
  if (flags != 0) {
    std::cout << "Skip flags:" << flags << std::endl;
    return false;
  }

  // Assume not empty.
  assert(count >= 1);
  if (count > 1) {
    descr->AddField(Metadata::Field(Metadata::Field::ARRAY_FIXED,
                                    field_name,
                                    count,
                                    parent));
    parent = descr->size() - 1;
  }

  // Decode each element of the array.
  for (size_t element = 0; element < count; ++element) {
    // Descriptor used to fetch properties information. Size 2 is
    // needed to fetch length of aggregate types.
    PROPERTY_DATA_DESCRIPTOR data_descriptors[2];
    unsigned int descriptor_count = 0;

    PBYTE name_ptr = reinterpret_cast<PBYTE>(pinfo) + field.NameOffset;
    data_descriptors[0].PropertyName = reinterpret_cast<ULONGLONG>(name_ptr);

    data_descriptors[0].ArrayIndex = element;
    descriptor_count = 1;

    // Determine the property size.
    ULONG property_size = 0;
    ULONG status = TdhGetPropertySize(pevent, 0, NULL, descriptor_count,
                                      &data_descriptors[0], &property_size);
    if (status != ERROR_SUCCESS)
      return false;

    // Get a pointer to a buffer large enough to hold the property.
    if (property_size > data_property_buffer_.size())
      data_property_buffer_.resize(property_size);
    ::memset(&data_property_buffer_[0], 0, data_property_buffer_.size());
    PBYTE raw_data = reinterpret_cast<PBYTE>(&data_property_buffer_[0]);
    
    // Retrieve the property.
    status = TdhGetProperty(pevent, 0, NULL, descriptor_count,
                            &data_descriptors[0], property_size, raw_data);
    if (status != ERROR_SUCCESS)
      return false;

    unsigned int in_type = field.nonStructType.InType;
    unsigned int out_type = field.nonStructType.OutType;

    FOR_EACH_ETW_OBSERVER(OnDecodePayloadField(this, parent, element,
                                               field_name, in_type, out_type,
                                               property_size, raw_data));

    // Decode the current field and append encoded value to the packet.
    Metadata::Field current_field;
    bool valid = DecodePayloadField(parent, field_name, in_type, out_type,
                                    property_size, raw_data, &current_field,
                                    packet);
    if (!valid)
      return false;

    // Validate that all elements in the array are compatible.
    if (element == 0) {
      merged_field = current_field;
      descr->AddField(merged_field);
    } else if (merged_field != current_field) {
      // Error when not the first elements and elements differ.
      return false;
    }
  }

  return true;
}

bool ETWConsumer::DecodePayloadField(size_t parent,
                                     const std::string& field_name,
                                     unsigned int in_type,
                                     unsigned int out_type,
                                     unsigned int property_size,
                                     void *raw_data,
                                     Metadata::Field* field,
                                     Metadata::Packet* packet) {
  assert(field != NULL);
  assert(packet != NULL);
  assert(!field_name.empty());
  assert(property_size != 0);

  // Try to decode the property with in/out type.
  Metadata::Field::FieldType field_type = Metadata::Field::INVALID;
  switch (in_type) {
    case TDH_INTYPE_UNICODESTRING:
      packet->EncodeString(ConvertString((LPWSTR)raw_data));
      // TODO(bergeret): We should keep unicode.
      *field = Metadata::Field(Metadata::Field::STRING, field_name, parent);
      return true;

    case TDH_INTYPE_ANSISTRING:
      packet->EncodeString((const char*)raw_data);
      *field = Metadata::Field(Metadata::Field::STRING, field_name, parent);
      return true;

    case TDH_INTYPE_UNICODECHAR:
      if (property_size == 2) {
        field_type = Metadata::Field::XINT16;
        packet->EncodeUInt16(*reinterpret_cast<uint16_t*>(raw_data));
        *field = Metadata::Field(field_type, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_ANSICHAR:
    case TDH_INTYPE_INT8:
    case TDH_INTYPE_UINT8:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT8:
          field_type = Metadata::Field::XINT8;
          break;
        case TDH_OUTTYPE_BYTE:
          field_type = Metadata::Field::INT8;
          break;
        case TDH_OUTTYPE_UNSIGNEDBYTE:
          field_type = Metadata::Field::UINT8;
          break;
        default:
          if (in_type == TDH_INTYPE_INT8) {
            field_type = Metadata::Field::INT8;
          } else {
            field_type = Metadata::Field::UINT8;
          }
          break;
      }

      if (property_size == 1) {
        packet->EncodeUInt8(*reinterpret_cast<uint8_t*>(raw_data));
        *field = Metadata::Field(field_type, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_INT16:
    case TDH_INTYPE_UINT16:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT16:
          field_type = Metadata::Field::XINT16;
          break;
        case TDH_OUTTYPE_SHORT:
          field_type = Metadata::Field::INT16;
          break;
        case TDH_OUTTYPE_UNSIGNEDSHORT:
          field_type = Metadata::Field::UINT16;
          break;
        default:
          if (in_type == TDH_INTYPE_INT16) {
            field_type = Metadata::Field::INT16;
          } else {
            field_type = Metadata::Field::UINT16;
          }
          break;
      }

      if (property_size == 2) {
        packet->EncodeUInt16(*reinterpret_cast<uint16_t*>(raw_data));
        *field = Metadata::Field(field_type, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_INT32:
    case TDH_INTYPE_UINT32:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT32:
          field_type = Metadata::Field::XINT32;
          break;
        case TDH_OUTTYPE_INT:
          field_type = Metadata::Field::INT32;
          break;
        case TDH_OUTTYPE_UNSIGNEDINT:
          field_type = Metadata::Field::UINT32;
          break;
        default:
          if (in_type == TDH_INTYPE_INT32) {
            field_type = Metadata::Field::INT32;
          } else {
            field_type = Metadata::Field::UINT32;
          }
          break;
      }

      if (property_size == 4) {
        packet->EncodeUInt32(*reinterpret_cast<uint32_t*>(raw_data));
        *field = Metadata::Field(field_type, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_INT64:
    case TDH_INTYPE_UINT64:
      switch (out_type) {
        case TDH_OUTTYPE_HEXINT64:
          field_type = Metadata::Field::XINT64;
          break;
        default:
          if (in_type == TDH_INTYPE_INT64) {
            field_type = Metadata::Field::INT64;
          } else {
            field_type = Metadata::Field::UINT64;
          }
          break;
      }

      if (property_size == 8) {
        packet->EncodeUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        *field = Metadata::Field(field_type, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_BOOLEAN:
      if (property_size == 1) {
        packet->EncodeUInt8(*reinterpret_cast<uint8_t*>(raw_data) != 0);
        *field = Metadata::Field(Metadata::Field::UINT8, field_name, parent);
        return true;
      } else if (property_size == 4) {
        packet->EncodeUInt8(*reinterpret_cast<uint32_t*>(raw_data) != 0);
        *field = Metadata::Field(Metadata::Field::UINT8, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_GUID:
      if (property_size == 16) {
        packet->EncodeBytes(reinterpret_cast<uint8_t*>(raw_data), 16);
        *field = Metadata::Field(Metadata::Field::GUID, field_name, parent);
        return true;
      }
      break;

    case TDH_INTYPE_POINTER:
    case TDH_INTYPE_SIZET:
      if (property_size == 4) {
        packet->EncodeUInt32(*reinterpret_cast<uint32_t*>(raw_data));
        *field = Metadata::Field(Metadata::Field::XINT32, field_name, parent);
        return true;
      } else if (property_size == 8) {
        packet->EncodeUInt64(*reinterpret_cast<uint64_t*>(raw_data));
        *field = Metadata::Field(Metadata::Field::XINT64, field_name, parent);
        return true;
      }
      break;
  }

  return false;
}

bool ETWConsumer::SerializeMetadata(std::string* result) const {
  assert(result != NULL);

  std::stringstream out;

  out << "/* CTF 1.8 */\n";

  // Define 'bit' type.
  out << "typealias integer "
      << "{ size = 1; align = 1; signed = false; } "
      << ":= bit;\n";

  // Define 'bit1' to 'bit32' types.
  for (int i = 1; i < 32; ++i) {
    out << "typealias integer { "
        << "size = " << i << "; "
        << "align = 1; "
        << "signed = false; "
        << "} := bit" << i << ";\n";
  }

  // Produce each standard size: 1, 2, 4 and 8 bytes.
  for (int i = 0; i < 4; ++i) {
    int size = (1 << i) * 8;

    // Define 'intX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = true; "
        << "} := int" << size << ";\n";

    // Define 'uintX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = false; "
        << "} := uint" << size << ";\n";

    // Define 'xintX' type.
    out << "typealias integer { "
        << "size = " << size << "; "
        << "align = 8; "
        << "signed = false; "
        << "base = 16; "
        << "} := xint" << size << ";\n";
  }
  out << "\n";

  out << "struct uuid {\n"
      << "  xint32 Data1;\n"
      << "  xint16 Data2;\n"
      << "  xint16 Data3;\n"
      << "  xint64 Data4;\n"
      << "};\n\n";

  out << "enum event_header_type : uint16 {\n"
      << "  EXT_TYPE_NONE,\n"
      << "  EXT_TYPE_RELATED_ACTIVITYID,\n"
      << "  EXT_TYPE_SID,\n"
      << "  EXT_TYPE_TS_ID,\n"
      << "  EXT_TYPE_INSTANCE_INFO,\n"
      << "  EXT_TYPE_STACK_TRACE32,\n"
      << "  EXT_TYPE_STACK_TRACE64\n"
      << "};\n\n";

  out << "struct event_header_flags {\n"
      << "  bit7 unused;\n"
      << "  bit FLAG_CLASSIC_HEADER;\n"
      << "  bit FLAG_64_BIT_HEADER;\n"
      << "  bit FLAG_32_BIT_HEADER;\n"
      << "  bit FLAG_NO_CPUTIME;\n"
      << "  bit FLAG_TRACE_MESSAGE;\n"
      << "  bit FLAG_STRING_ONLY;\n"
      << "  bit FLAG_PRIVATE_SESSION;\n"
      << "  bit FLAG_EXTENDED_INFO;\n"
      << "};\n\n";

  out << "struct event_header_properties {\n"
      << "  bit13 unused;\n"
      << "  bit EVENT_HEADER_PROPERTY_LEGACY_EVENTLOG;\n"
      << "  bit EVENT_HEADER_PROPERTY_FORWARDED_XML;\n"
      << "  bit EVENT_HEADER_PROPERTY_XML;\n"
      << "};\n\n";

  std::string guid_str = GuidToString(ETWConverterGuid);

  out << "trace {\n"
      << "  major = 1;\n"
      << "  minor = 8;\n"
      << "  uuid  = \"" << guid_str << "\";\n"
      << "  byte_order = le;\n"
      << "  packet.header := struct {\n"
      << "    uint32  magic;\n"
      << "    xint8   uuid[16];\n"
      << "  };\n"
      << "};\n\n";

  out << "stream {\n"
      << "  packet.context := struct {\n"
      << "    uint32  content_size;\n"
      << "    uint32  packet_size;\n"
      << "    uint64  timestamp_begin;\n"
      << "    uint64  timestamp_end;\n"
      << "  };\n"
      << "  event.header := struct {\n"
      << "    uint64  timestamp;\n"
      << "    uint32  id;\n"
      << "  };\n"
      << "  event.context := struct {\n"
      << "    uint16  ev_id;\n"
      << "    uint8   ev_version;\n"
      << "    uint8   ev_channel;\n"
      << "    uint8   ev_level;\n"
      << "    uint8   ev_opcode;\n"
      << "    uint16  ev_task;\n"
      << "    xint64  ev_keyword;\n"
      << "    uint32  pid;\n"
      << "    uint32  tid;\n"
      << "    uint8   cpu_id;\n"
      << "    uint16  logger_id;\n"
      << "    struct  uuid provider_id;\n"
      << "    struct  uuid activity_id;\n"
      << "    enum    event_header_type header_type;\n"
      << "    xint16  header_flags;\n"
      << "    struct  event_header_flags header_flags_decoded;\n"
      << "    xint16  header_properties;\n"
      << "    struct  event_header_properties header_properties_decoded;\n"
      << "  };\n"
      << "};\n\n";

  out << "event {\n"
      << "  id = 0;\n"
      << "  name = \"unknown\";\n"
      << "  fields := struct {\n"
      << "    uint8   cpuid;\n"  // TODO(etienneb): May clash with a field.
      << "  };\n"
      << "};\n\n";

  // For each event layout in our dictionary, produce the CTF metadata.
  for (size_t i = 0; i < metadata_.size(); ++i) {
    size_t event_id = i + 1;
    const Metadata::Event& descr = metadata_.GetEventWithId(i);
    if (!SerializeMetadataEvent(descr, event_id, &out)) {
      std::cerr << "Cannot serialize metadata." << std::endl;
      return false;
    }
  }

  // Commit the result.
  *result = out.str();
  return true;
}

bool ETWConsumer::SerializeMetadataEvent(const Metadata::Event& descr,
                                         size_t event_id,
                                         std::stringstream* out) const {
  assert(out != NULL);

  std::string guid = GuidToString(descr.guid());
  *out << "// guid: " << guid
       << " opcode:" << static_cast<unsigned int>(descr.opcode())
       << " version:" << static_cast<unsigned int>(descr.version())
       << " id:" << descr.event_id()
       << "\n";
  *out << "event {\n"
       << "  id = " << event_id << ";\n";

  if (descr.name().empty()) {
    *out << "  name = \"event" << event_id << "\";\n";
  } else {
    *out << "  name = \"" << descr.name() << "\";\n";
  }

  // Event Fields
  *out <<"  fields := struct {\n"
       << "    uint8   cpuid;\n";  // TODO(etienneb): May clash with a field.

  for (size_t i = 0; i < descr.size(); ++i) {
    if (!SerializeMetadataField(descr, descr.at(i), out))
      return false;
  }
  *out <<"  };\n";

  *out <<"};\n\n";

  return true;
}

bool ETWConsumer::SerializeMetadataField(const Metadata::Event& descr,
                                         const Metadata::Field& field,
                                         std::stringstream* out) const {
  assert(out != NULL);

  // Indent this field.
  for (size_t p = field.parent(); p != kRootScope; p = descr.at(p).parent()) {
    const Metadata::Field::FieldType type = descr.at(p).type();
    if (type == Metadata::Field::STRUCT_BEGIN)
      *out << "  ";
  }

  // Dispatch the field type.
  switch (field.type()) {
  case Metadata::Field::ARRAY_FIXED:
  case Metadata::Field::ARRAY_VAR:
    return true;

  case Metadata::Field::STRUCT_BEGIN:
    *out << "    struct  {\n";
    return true;
  case Metadata::Field::STRUCT_END:
    *out << "    } " << descr.at(field.parent()).name();
    break;
  case Metadata::Field::BINARY_FIXED:
    *out << "    uint8   " << field.name()
         << "[" << field.size() << "]";
    break;
  case Metadata::Field::BINARY_VAR:
    *out << "    uint8   " << field.name()
         << "[" << field.field_size() << "]";
    break;
  case Metadata::Field::INT8:
    *out << "    int8    " << field.name();
    break;
  case Metadata::Field::INT16:
    *out << "    int16   " << field.name();
    break;
  case Metadata::Field::INT32:
    *out << "    int32   " << field.name();
    break;
  case Metadata::Field::INT64:
    *out << "    int64   " << field.name();
    break;
  case Metadata::Field::UINT8:
    *out << "    uint8   " << field.name();
    break;
  case Metadata::Field::UINT16:
    *out << "    uint16  " << field.name();
    break;
  case Metadata::Field::UINT32:
    *out << "    uint32  " << field.name();
    break;
  case Metadata::Field::UINT64:
    *out << "    uint64  " << field.name();
    break;
  case Metadata::Field::XINT8:
    *out << "    xint8   " << field.name();
    break;
  case Metadata::Field::XINT16:
    *out << "    xint16  " << field.name();
    break;
  case Metadata::Field::XINT32:
    *out << "    xint32  " << field.name();
    break;
  case Metadata::Field::XINT64:
    *out << "    xint64  " << field.name();
    break;
  case Metadata::Field::STRING:
    *out << "    string  " << field.name();
    break;
  case Metadata::Field::GUID:
    *out << "    struct  uuid  "<< field.name();
    break;
  default:
    return false;
  }

  // Output the aggregate declaration suffix.
  for (size_t p = field.parent(); p != kRootScope; p = descr.at(p).parent()) {
    const Metadata::Field& parent = descr.at(p);
    if (parent.type() == Metadata::Field::ARRAY_FIXED) {
      *out << "[" << parent.size() << "]";
    } else if (parent.type() == Metadata::Field::ARRAY_VAR) {
      *out << "[" << parent.field_size() << "]";
    } else {
      break;
    }
  }

  // End of declaration.
  *out << ";\n";

  return true;
}

}  // namespace converter
