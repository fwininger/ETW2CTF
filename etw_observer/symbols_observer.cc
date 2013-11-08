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
// Observes the processed ETW events and adds debug information to the
// converted trace.

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT
#include <tdh.h>

#include <cassert>
#include <set>
#include <string>

#include "base/compiler_specific.h"
#include "base/disallow_copy_and_assign.h"
#include "base/logging.h"
#include "converter/etw_consumer.h"
#include "converter/metadata.h"
#include "etw_observer/etw_observer.h"
#include "etw_observer/etw_observer_utils.h"
#include "sym_util/image.h"
#include "sym_util/symbol_lookup_service.h"

namespace {

using converter::ETWConsumer;
using converter::Metadata;
using etw_observer::CaptureLong;
using etw_observer::CaptureUint32;

// GUID of the Symbols provider.
const GUID kSymbolsProviderGUID = {
    0x186fbaef, 0x0e6a, 0x45a9, 0xa1, 0xad, 0x90, 0xa1, 0x0b, 0x69, 0x56, 0x69};

// GUID of Symbols events.
const GUID kSymbolsEventGUID = {
    0x6739acc2, 0xe99c, 0x48f7, 0xbb, 0x69, 0x5b, 0x13, 0x90, 0x15, 0x90, 0xd5};

// Version of Symbols events.
const unsigned char kSymbolsEventVersion = 1;

// Opcode of Symbols "ImageId" events.
const unsigned char kImageIdOpcode = 0x0a;

// Name of Symbols "ImageId" events.
const char* kImageIdEventName = "ImageId";

// Opcode of Symbols "SymbolInfo" events.
const unsigned char kSymbolInfoOpcode = 0x0b;

// Name of Symbols "SymbolInfo" events.
const char* kSymbolInfoEventName = "SymbolInfo";

// Name of the image identifier field in Symbols events.
const char* kImageIdentifierFieldName = "ImageIdentifier";

// Name of the symbol name field in Symbols events.
const char* kSymbolNameFieldName = "SymbolName";

// Name of the symbol address field in Symbols events.
const char* kSymbolAddressFieldName = "SymbolAddress";

// GUID of Image events.
// See http://msdn.microsoft.com/library/windows/desktop/aa364070.aspx
const GUID kImageEventGUID = {
    0x2cb15d1d, 0x5fc1, 0x11d2, 0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18};

// Opcode of Image "DCStart" events.
const unsigned char kImageDCStartOpcode = 3;

// Opcode of Image "Load" events.
const unsigned char kImageLoadOpcode = 10;

// Name of the fields of Image events.
const char* kImageBaseFieldName = "ImageBase";
const char* kImageSizeFieldName = "ImageSize";
const char* kImageChecksumFieldName = "ImageChecksum";
const char* kImageTimestampFieldName = "TimeDateStamp";
const char* kImageFileNameFieldName = "FileName";

// Parameter for the callback used to enumerate the symbols of an image.
struct EnumerateSymbolsCallbackParams {
  // Identifier of the image that is being processed.
  size_t image_id;

  // ETW consumer to use to send new events.
  ETWConsumer* consumer;

  // Timestamp of generated events.
  uint64_t timestamp;
};

// Callback called for each symbol of an image.
// See documentation of PSYMBOL_REGISTERED_CALLBACKW64.
BOOL CALLBACK EnumerateSymbolsCallback(PCWSTR SymbolName,
                                       DWORD64 SymbolAddress,
                                       ULONG SymbolSize,
                                       PVOID UserContext) {
  EnumerateSymbolsCallbackParams* params =
      reinterpret_cast<EnumerateSymbolsCallbackParams*>(UserContext);
  assert(params != NULL);

  ETWConsumer* consumer = params->consumer;
  assert(consumer != NULL);

  // Generate an event with the symbol information.
  Metadata::Packet packet;
  ETWConsumer::EncodeGeneratedEventHeader(params->timestamp,
                                          kSymbolInfoOpcode,
                                          kSymbolsEventVersion,
                                          kSymbolsProviderGUID,
                                          &packet);
  Metadata::Event descr;
  descr.set_info(kSymbolsEventGUID, kSymbolInfoOpcode, kSymbolsEventVersion, 0);
  descr.set_name(kSymbolInfoEventName);

  descr.AddField(Metadata::Field(Metadata::Field::XINT64,
                                 kImageIdentifierFieldName,
                                 Metadata::kRootScope));
  packet.EncodeUInt64(params->image_id);

  // TODO(fdoray): Support Unicode.
  descr.AddField(Metadata::Field(Metadata::Field::STRING,
                                 kSymbolNameFieldName,
                                 Metadata::kRootScope));
  std::wstring symbol_name_wstr(SymbolName);
  std::string symbol_name_str(symbol_name_wstr.begin(),
                              symbol_name_wstr.end());
  packet.EncodeString(symbol_name_str);

  descr.AddField(Metadata::Field(Metadata::Field::XINT64,
                                 kSymbolAddressFieldName,
                                 Metadata::kRootScope));
  packet.EncodeUInt64(SymbolAddress);

  consumer->FinalizePacket(descr, &packet);
  consumer->AddPacketToSendingQueue(packet);

  return TRUE;
}

class SymbolsObserver : public etw_observer::ETWObserver {
 public:
  SymbolsObserver();

 private:
  // Override etw_observer::ETWObserver:
  // @{
  virtual void OnExtractEventInfo(ETWConsumer* consumer,
                                  PEVENT_RECORD pevent,
                                  PTRACE_EVENT_INFO pinfo) OVERRIDE;
  virtual void OnDecodePayloadField(ETWConsumer* consumer,
                                    size_t parent,
                                    size_t array_offset,
                                    const std::string& field_name,
                                    unsigned int in_type,
                                    unsigned int out_type,
                                    ULONG property_size,
                                    void* raw_data) OVERRIDE;
  virtual void OnEndProcessEvent(ETWConsumer* consumer,
                                 PEVENT_RECORD pevent) OVERRIDE;
  // @}

  // Indicates whether the event that is currently being processed by the
  // observed ETW consumer is of type Image, with opcode DCStart or Load.
  bool is_loading_image_;

  // Information about the image described in the Image event that is currently
  // being processed, if applicable.
  sym_util::Image image_;

  // Symbol lookup service, used to enumerate the symbols of an image.
  sym_util::SymbolLookupService symbol_lookup_service_;

  // Images for which symbols have already been enumerated. Images are not
  // identical if they are not loaded at the same base address.
  std::set<sym_util::Image> processed_images_;

  DISALLOW_COPY_AND_ASSIGN(SymbolsObserver);
} symbols_observer;

SymbolsObserver::SymbolsObserver() : is_loading_image_(false) {}

void SymbolsObserver::OnExtractEventInfo(ETWConsumer* consumer,
                                         PEVENT_RECORD pevent,
                                         PTRACE_EVENT_INFO pinfo) {
  assert(consumer != NULL);
  assert(pevent != NULL);
  assert(pinfo != NULL);

  // OnEndProcessEvent() should always set |is_loading_image_| to false before
  // this method is called again for a new event.
  assert(is_loading_image_ == false);

  const unsigned char event_opcode = pevent->EventHeader.EventDescriptor.Opcode;
  if (IsEqualGUID(pinfo->EventGuid, kImageEventGUID) &&
      (event_opcode == kImageDCStartOpcode ||
       event_opcode == kImageLoadOpcode)) {
    is_loading_image_ = true;
    image_.Reset();
  }
}

void SymbolsObserver::OnDecodePayloadField(ETWConsumer* consumer,
                                           size_t parent,
                                           size_t array_offset,
                                           const std::string& field_name,
                                           unsigned int in_type,
                                           unsigned int out_type,
                                           ULONG property_size,
                                           void* raw_data) {
  assert(consumer != NULL);
  assert(raw_data != NULL);

  if (!is_loading_image_)
    return;

  if (field_name == kImageBaseFieldName) {
    if (!CaptureLong(in_type, property_size, raw_data, &image_.base_address))
      NOTREACHED();
  } else if (field_name == kImageSizeFieldName) {
    if (!CaptureLong(in_type, property_size, raw_data, &image_.size))
      NOTREACHED();
  } else if (field_name == kImageChecksumFieldName) {
    if (!CaptureUint32(in_type, property_size, raw_data, &image_.checksum))
      NOTREACHED();
  } else if (field_name == kImageTimestampFieldName) {
    if (!CaptureUint32(in_type, property_size, raw_data, &image_.timestamp))
      NOTREACHED();
  } else if (field_name == kImageFileNameFieldName) {
    assert(in_type == TDH_INTYPE_UNICODESTRING);
    image_.filename = reinterpret_cast<wchar_t*>(raw_data);
  }
}

void SymbolsObserver::OnEndProcessEvent(ETWConsumer* consumer,
                                        PEVENT_RECORD pevent) {
  assert(consumer != NULL);
  assert(pevent != NULL);

  if (!is_loading_image_)
    return;
  is_loading_image_ = false;

  // Don't enumerate the symbols of an image twice.
  if (processed_images_.find(image_) != processed_images_.end())
    return;

  // Create an event that associates an identifier with this image.
  Metadata::Packet packet;
  ETWConsumer::EncodeGeneratedEventHeader(
      pevent->EventHeader.TimeStamp.QuadPart,
      kImageIdOpcode,
      kSymbolsEventVersion,
      kSymbolsProviderGUID,
      &packet);
  Metadata::Event descr;
  descr.set_info(kSymbolsEventGUID, kImageIdOpcode,
                 kSymbolsEventVersion, 0);
  descr.set_name(kImageIdEventName);

  // Populate packet fields.
  descr.AddField(Metadata::Field(Metadata::Field::XINT64,
                                 kImageBaseFieldName, Metadata::kRootScope));
  packet.EncodeUInt64(image_.base_address);

  descr.AddField(Metadata::Field(Metadata::Field::UINT64,
                                 kImageSizeFieldName, Metadata::kRootScope));
  packet.EncodeUInt64(image_.size);

  descr.AddField(Metadata::Field(Metadata::Field::UINT32,
                                 kImageChecksumFieldName,
                                 Metadata::kRootScope));
  packet.EncodeUInt32(image_.checksum);

  descr.AddField(Metadata::Field(Metadata::Field::UINT32,
                                 kImageTimestampFieldName,
                                 Metadata::kRootScope));
  packet.EncodeUInt32(image_.timestamp);

  // TODO(fdoray): Support Unicode.
  descr.AddField(Metadata::Field(Metadata::Field::STRING,
                                 kImageFileNameFieldName,
                                 Metadata::kRootScope));
  std::string filename(image_.filename.begin(), image_.filename.end());
  packet.EncodeString(filename);

  descr.AddField(Metadata::Field(Metadata::Field::XINT64,
                                 kImageIdentifierFieldName,
                                 Metadata::kRootScope));
  packet.EncodeUInt64(processed_images_.size());

  // Push the generated event to the sending queue.
  consumer->FinalizePacket(descr, &packet);
  consumer->AddPacketToSendingQueue(packet);

  // Create a parameters structure for the symbol enumeration callback.
  EnumerateSymbolsCallbackParams enumerate_symbols_params;
  enumerate_symbols_params.image_id = processed_images_.size();
  enumerate_symbols_params.consumer = consumer;
  enumerate_symbols_params.timestamp = pevent->EventHeader.TimeStamp.QuadPart;

  // Enumerate all symbols.
  symbol_lookup_service_.Initialize();
  symbol_lookup_service_.EnumerateSymbols(image_,
                                          EnumerateSymbolsCallback,
                                          &enumerate_symbols_params);

  // Remember that this image has been processed.
  processed_images_.insert(image_);
}

}  // namespace
