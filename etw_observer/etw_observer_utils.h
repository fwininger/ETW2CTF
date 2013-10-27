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

#ifndef ETW_OBSERVER_ETW_OBSERVER_UTILS_H_
#define ETW_OBSERVER_ETW_OBSERVER_UTILS_H_

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT

#include <cstdint>

namespace etw_observer {

// Copy |raw_data| in |out| if its type is compatible with uint32_t.
// @param in_type type of |raw_data| on input.
// @param property_size size of |raw_data|, in bytes.
// @param raw_data the data to copy.
// @param out the destination of the copy.
// @returns true if the value has been captured, false otherwise.
bool CaptureUint32(unsigned int in_type, ULONG property_size, void* raw_data,
                   uint32_t* out);

// Copy |raw_data| in |out| if its type is compatible with uint64_t.
// @param in_type type of |raw_data| on input.
// @param property_size size of |raw_data|, in bytes.
// @param raw_data the data to copy.
// @param out the destination of the copy.
// @returns true if the value has been captured, false otherwise.
bool CaptureUint64(unsigned int in_type, ULONG property_size, void* raw_data,
                   uint64_t* out);

// Copy |raw_data| in |out| if it's a 32 or 64 bits unsigned integer. 
// @param in_type type of |raw_data| on input.
// @param property_size size of |raw_data|, in bytes.
// @param raw_data the data to copy.
// @param out the destination of the copy.
// @returns true if the value has been captured, false otherwise.
bool CaptureLong(unsigned int in_type, ULONG property_size, void* raw_data,
                 uint64_t* out);

}  // namespace etw_observer

#endif  // ETW_OBSERVER_ETW_OBSERVER_UTILS_H_
