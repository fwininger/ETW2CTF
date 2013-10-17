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
// An ETW observer is notified at different steps of the processing of
// ETW events.
//
// ETW observers use a self registry mechanism. Do not instantiate an
// observer with new. Only static instantiation will work safely.
//
// Example:
//  class DummyObserver : public ETWObserver {
//   public:
//    DummyObserver() {}
//    virtual void OnBeginProcessEvent( ... ) { ... }
//    virtual void OnDecodePayloadField( ... ) { ... }
//    virtual void OnEndProcessEvent( ... ) { ... }
// } dummy; // Performs the auto registry.

#ifndef ETW_OBSERVER_ETW_OBSERVER_H_
#define ETW_OBSERVER_ETW_OBSERVER_H_

// Restrict the import to the Windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT
#include <evntcons.h>
#include <string>

namespace converter {
class ETWConsumer;
}  // namespace converter

namespace etw_observer {

class ETWObserver {
 public:
  ETWObserver();
  virtual ~ETWObserver() {}

  // Called when an ETW consumer starts processing an event.
  // @param consumer the observed consumer.
  // @param pevent the ETW event that is processed.
  virtual void OnBeginProcessEvent(converter::ETWConsumer* consumer,
                                   PEVENT_RECORD pevent) {}

  // Called when a payload field is decoded. Is only called between calls to
  // OnBeginProcessEvent() and OnEndProcessEvent().
  // @param consumer the observed consumer.
  // @param parent parent of the field.
  // @param array_offset offset of the field in an array or 0 if the field is
  //     not part of an array.
  // @param field_name name of the field.
  // @param in_type data type of the field on input.
  // @param out_type data type of the field on output.
  // @param property_size size of the field, in bytes.
  // @param raw_data pointer to the raw data of the field.
  virtual void OnDecodePayloadField(converter::ETWConsumer* consumer,
                                    size_t parent,
                                    size_t array_offset,
                                    const std::string& field_name,
                                    unsigned int in_type,
                                    unsigned int out_type,
                                    ULONG property_size,
                                    void* raw_data) {}

  // Called when an ETW consumer finishes to process an event.
  // @param consumer the observed consumer.
  // @param pevent the ETW event that is processed.
  virtual void OnEndProcessEvent(converter::ETWConsumer* consumer,
                                 PEVENT_RECORD pevent) {}

  // @returns the next registered observer.
  ETWObserver* next() { return next_; }

 private:
  // Anchor for a linked list of observers.
  ETWObserver* next_;
};

// @returns the first registered ETW observer or NULL if there is no
//     registered observer.
ETWObserver* GetFirstETWObserver();

}  // namespace etw_observer

// Macro to call a method on each registered ETW observer.
// Sample usage:
//     FOR_EACH_ETW_OBSERVER(OnBeginProcessEvent(this, pevent));
#define FOR_EACH_ETW_OBSERVER(func)                                            \
  do {                                                                         \
    etw_observer::ETWObserver* it_inside_observer_macro =                      \
        etw_observer::GetFirstETWObserver();                                   \
    while (it_inside_observer_macro != NULL) {                                 \
      it_inside_observer_macro->func;                                          \
      it_inside_observer_macro = it_inside_observer_macro->next();             \
    }                                                                          \
  } while (0)

#endif  // ETW_OBSERVER_ETW_OBSERVER_H_