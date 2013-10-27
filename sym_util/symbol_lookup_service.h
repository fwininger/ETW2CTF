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

#ifndef SYM_UTIL_SYMBOL_LOOKUP_SERVICE_H_
#define SYM_UTIL_SYMBOL_LOOKUP_SERVICE_H_

// Restrict the import to the windows basic includes.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>  // NOLINT
// Add Unicode support to DbgHelp functions.
#define DBGHELP_TRANSLATE_TCHAR
#include <dbghelp.h>

#include "base/disallow_copy_and_assign.h"
#include "sym_util/image.h"

namespace sym_util {

// Interface to DbgHelp to easily enumerate the symbols of an image.
class SymbolLookupService {
 public:
  SymbolLookupService();
  ~SymbolLookupService();

  // Initializes the symbol cache.
  // @returns true if the initialization is successful, false otherwise.
  bool Initialize();

  // Enumerates all the symbols of the specified image.
  // @param image image for which to enumerate the symbols.
  // @param callback function that will be called for each symbol of the image.
  // @param user_context user-defined value that is passed to the callback
  //     function. Can be NULL.
  // @returns true if the symbols have been enumerated correctly, false
  //     otherwise. Returns false when no debug information is found for the
  //     image.
  bool EnumerateSymbols(const Image& image,
                        PSYM_ENUMSYMBOLS_CALLBACK64W callback,
                        PVOID user_context);

 private:
  // Indicates whether the service has been initialized successfully.
  bool initialized_;

  // Handle that identifies the DbgHelp session.
  HANDLE dbghelp_handle_;

  DISALLOW_COPY_AND_ASSIGN(SymbolLookupService);
};

}  // namespace sym_util

#endif  // SYM_UTIL_SYMBOL_LOOKUP_SERVICE_H_
