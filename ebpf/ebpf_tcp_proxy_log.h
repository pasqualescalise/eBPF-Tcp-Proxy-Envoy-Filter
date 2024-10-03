/*
 * Copyright 2024 Sebastiano Miano <mianosebastiano@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef BPF_LOG_H_
#define BPF_LOG_H_

#include <stddef.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define BPF_LOG_DISABLED  (0)
#define BPF_LOG_ERR (1)
#define BPF_LOG_WARNING (2)
#define BPF_LOG_NOTICE (3)
#define BPF_LOG_INFO (4)
#define BPF_LOG_DEBUG (5)

#ifndef BPF_LOG_LEVEL
#define BPF_LOG_LEVEL BPF_LOG_DISABLED
#endif

#define bpf_log_err(...) (BPF_LOG_LEVEL < BPF_LOG_ERR ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_warning(...) (BPF_LOG_LEVEL < BPF_LOG_WARNING ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_notice(...) BPF_LOG_LEVEL < BPF_LOG_NOTICE ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_info(...) (BPF_LOG_LEVEL < BPF_LOG_INFO ? (0) : bpf_printk(__VA_ARGS__))
#define bpf_log_debug(...) (BPF_LOG_LEVEL < BPF_LOG_DEBUG ? (0) : bpf_printk(__VA_ARGS__))

#endif // BPF_LOG_H_