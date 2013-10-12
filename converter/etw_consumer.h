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
// Implementation of the ETW consumer.

#ifndef CONVERTER_ETW_CONSUMER_H_
#define CONVERTER_ETW_CONSUMER_H_

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NO LINT
// Turns the DEFINE_GUID for EventTraceGuid into a const.
#define INITGUID
#include <guiddef.h>
#include <evntcons.h>
#include <tdh.h>

#include <cassert>
#include <list>
#include <string>
#include <vector>

#include "converter/metadata.h"

namespace converter {

// The ETW consumer uses the windows API to consume ETW events. By using the
// Trace Data Helper (THD), the converter decodes payloads and event layouts.
// Decoded payloads are serialized into CTF packets.
class ETWConsumer {
 public:
  ETWConsumer()
      : event_callback_(NULL),
        buffer_callback_(NULL),
        packet_total_bytes_(0),
        packet_maximal_size_(0) {
  }

  // Check whether the list of registered trace is empty.
  // @returns true when there are no traces to consume, false otherwise.
  bool Empty() const { return traces_.empty(); }

  // Add a trace file for consuming.
  // @param filename the path to the trace file.
  void AddTraceFile(std::wstring filename) {
    traces_.push_back(filename);
  }

  // Set the global event callback called by the Windows API.
  // This callback must be a trampoline to this->ProcessEvent(...).
  // @param ec the callback to be called for each event.
  void SetEventCallback(PEVENT_RECORD_CALLBACK ec) {
    assert(ec != NULL);
    event_callback_ = ec;
  }

  // Set the global buffer callback called by the Windows API.
  // This callback must be a trampoline to this->ProcessBuffer(...).
  // @param bc the callback called for each buffer.
  void SetBufferCallback(PEVENT_TRACE_BUFFER_CALLBACK bc) {
    assert(bc != NULL);
    buffer_callback_ = bc;
  }

  // Set the maximal CTF packet size.
  // @param size The maximal packet size.
  void set_packet_maximal_size(size_t size) { packet_maximal_size_ = size; }

  // Consume all registered trace files.
  // @returns true on success, false if an error occurred.
  bool ConsumeAllEvents();

  // For a given ETW buffer, produce a unique CTF stream name.
  // @param ptrace the ETW buffer information.
  // @param name receives the stream name.
  // @returns true on success, false otherwise.
  bool GetBufferName(PEVENT_TRACE_LOGFILE ptrace, std::wstring* name) const;

  // Callback called for each ETW event. The ETW event is serialized into a
  // CTF packet.
  // @param pevent the ETW event to convert.
  // @returns true on success, false otherwise.
  bool ProcessEvent(PEVENT_RECORD pevent);

  // Callback called at the beginning of each ETW buffer.
  // @param ptrace the ETW buffer information.
  // @returns true on success, false otherwise.
  bool ProcessBuffer(PEVENT_TRACE_LOGFILE ptrace);

  // Serialize the metadata to the CTF text representation.
  // @param results on success, receives the metadata text representation.
  // @returns true on success, false otherwise.
  bool SerializeMetadata(std::string* results) const;

  // Check if pending packets can make a full packet.
  // @returns true if there is enough pending bytes.
  bool IsFullPacketReady();

  // Check if the pending queue is empty.
  // @return true if the queue is empty, false otherwise.
  bool IsSendingQueueEmpty();

  // Remove the pending packets and build a full packet ready to send.
  // @param packet Receives the full packet.
  void BuildFullPacket(Metadata::Packet* packet);

 private:
  bool DecodePayload(
      PEVENT_RECORD pevent, Metadata::Packet* packet, Metadata::Event* descr);
  bool SendRawPayload(
      PEVENT_RECORD pevent, Metadata::Packet* packet, Metadata::Event* descr);

  bool DecodePayloadField(PEVENT_RECORD pevent, PTRACE_EVENT_INFO pinfo,
      unsigned int field, Metadata::Packet* packet, Metadata::Event* descr);

  bool SendRawPayloadField(PEVENT_RECORD pevent,
                           PTRACE_EVENT_INFO pinfo,
                           unsigned int field,
                           Metadata::Packet* packet,
                           Metadata::Event* descr) const;

  bool SerializeMetadataEvent(const Metadata::Event& descr,
                              size_t id,
                              std::stringstream* out) const;
  bool SerializeMetadataField(const Metadata::Field& field,
                              std::stringstream* out) const;

  void EncodePacketHeader(Metadata::Packet* packet,
                          size_t* packet_context_offset);
  void UpdatePacketHeader(size_t packet_context_offset,
                          uint32_t content_size,
                          uint32_t packet_size,
                          Metadata::Packet* packet);

  void AddPacketToSendingQueue(const Metadata::Packet& packet);
  void PopPacketFromSendingQueue();

  // Trace files to consume.
  std::vector<std::wstring> traces_;

  // Callbacks to register to the ETW API.
  PEVENT_RECORD_CALLBACK event_callback_;
  PEVENT_TRACE_BUFFER_CALLBACK buffer_callback_;

  // The dictionary of event layouts.
  Metadata metadata_;

  // A pending queue of packets to send.
  std::list<const Metadata::Packet> packets_;

  // The total number of bytes in pending queue.
  size_t packet_total_bytes_;

  // The threshold before merging and sending pending packets.
  size_t packet_maximal_size_;

  // Temporary buffer used to hold raw data produced by the ETW API.
  std::vector<char> data_property_buffer_;
  std::vector<char> packet_info_buffer_;
};

}  // namespace converter

#endif  // CONVERTER_ETW_CONSUMER_H_
