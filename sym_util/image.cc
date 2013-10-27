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

#include "sym_util/image.h"

#include <cassert>

namespace sym_util {

Image::Image() : base_address(0), size(0), checksum(0), timestamp(0) {}

bool Image::operator<(const Image& image) const {
  if (base_address < image.base_address)
    return true;
  if (base_address > image.base_address)
    return false;
  assert(base_address == image.base_address);

  if (size < image.size)
    return true;
  if (size > image.size)
    return false;
  assert(size == image.size);

  if (checksum < image.checksum)
    return true;
  if (checksum > image.checksum)
    return false;
  assert(checksum == image.checksum);

  if (timestamp < image.timestamp)
    return true;
  if (timestamp > image.timestamp)
    return false;
  assert(timestamp == image.timestamp);

  return filename < image.filename;
}

void Image::Reset() {
  base_address = 0;
  size = 0;
  checksum = 0;
  timestamp = 0;
  filename = std::wstring();
}

}  // namespace sym_util
