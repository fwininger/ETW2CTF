# Copyright (c) 2013 The ETW2CTF Authors.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the <organization> nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

{
  'includes': [
    'etw2ctf.gypi',
  ],
  'targets': [
    {
      'target_name': 'etw2ctf',
      'type': 'executable',
      'msvs_settings': {
        'VCLinkerTool': {
          'AdditionalDependencies': [
            'advapi32.lib',
            'dbghelp.lib',
            'tdh.lib',
          ],
          'DelayLoadDLLs': [
            # Delay loading dbghelp.dll so that the library installed with
            # Windows Performance Toolkit can be loaded programmatically instead
            # of the default one. This is important because the default library
            # cannot communicate with a symbol server.
            'dbghelp.dll',
          ],
        },
      },
      'sources': [
        # TODO(fdoray): Use .cc extension instead of .cpp.
        'main.cpp',
        'base/compiler_specific.h',
        'base/disallow_copy_and_assign.h',
        'base/scoped_handle.cc',
        'base/scoped_handle.h',
        'converter/ctf_producer.cpp',
        'converter/ctf_producer.h',
        'converter/etw_consumer.cpp',
        'converter/etw_consumer.h',
        'converter/metadata.cpp',
        'converter/metadata.h',
        'dissector/dissectors.cpp',
        'dissector/dissectors.h',
        'etw_observer/etw_observer.cpp',
        'etw_observer/etw_observer.h',
        'sym_util/image.cc',
        'sym_util/image.h',
        'sym_util/load_dbghelp.cc',
        'sym_util/load_dbghelp.h',
        'sym_util/symbol_lookup_service.cc',
        'sym_util/symbol_lookup_service.h',
      ],
    },
  ]
}
