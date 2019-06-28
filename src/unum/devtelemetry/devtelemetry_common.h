// Copyright 2018 Minim Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// devices telemetry subsystem common include file

#ifndef _DEVTELEMETRY_COMMON_H
#define _DEVTELEMETRY_COMMON_H


// Number of time slot intervals (the TPCAP_TIME_SLICE intervals) in
// each telemetry transmission
#define DEVTELEMETRY_NUM_SLICES 1


// Pull in data tables structures
#include "dt_data_tables.h"

// Pull in the festats include (festats is essentially a dev telemetry's
// subsystem, so do it here rather than in the unum.h)
#include "../festats/festats.h"


// Get the interface counters and capturing stats
DT_IF_STATS_t *dt_get_if_stats(void);

// This functon handles adding festats connection info to devices
// telemetry. It's unused for platforms that do not support festats.
// Returns: TRUE - connection info added, FALSE - unable to add
//          all or some of the info
int dt_add_fe_conn(FE_CONN_t *fe_conn);

// Reset all DNS tables (including the table usage stats)
void dt_reset_dns_tables(void);

// Get the pointer to the DNS ip addresses table
// The table should only be accessed from the tpcap thread
DT_DNS_IP_t *dt_get_dns_ip_tbl(void);

// Get the pointer to the devices table
// The table should only be accessed from the tpcap thread
DT_DEVICE_t **dt_get_dev_tbl(void);

// Generate and pass to the sender the devices telemetry JSON.
// If the previously submitted JSON buffer is not yet consumed
// replace it with the new one.
// The function is called from the TPCAP thread/handler.
// Avoid blocking if possible.
void dt_sender_data_ready(void);

// Returns pointer to the DNS name table stats.
// Use from the tpcap callbacks only.
// Subsequent calls override the data.
// Pass TRUE to reset the table (allows to get data and reset in one call)
DT_TABLE_STATS_t *dt_dns_name_tbl_stats(int reset);

// Returns pointer to the DNS IP table stats.
// Use from the tpcap callbacks only.
// Subsequent calls override the data.
// Pass TRUE to reset the table (allows to get data and reset in one call)
DT_TABLE_STATS_t *dt_dns_ip_tbl_stats(int reset);

// Returns pointer to the devices table stats.
// Use from the tpcap callbacks only.
// Subsequent calls override the data.
// Pass TRUE to reset the table (allows to get data and reset in one call)
DT_TABLE_STATS_t *dt_dev_tbl_stats(int reset);

// INCOMPLETE: (lmower 20190628)
// Currently only a mechanism to be used as a callback for logging
// DHCP offer packets. Should time allow, the same pattern of using
// tables would be applied to DHCP information and report on things
// such whether more than one DHCP server is issuing IPs on the lan
// This will ultimately be defined like the other, e.g.
// DT_TABLE_STATS_t *dt_dhcp_tbl_stats(int reset);
void dt_dhcp_tbl_stats(void);

// Returns pointer to the connections table stats.
// Use from the tpcap callbacks only.
// Subsequent calls override the data.
// Pass TRUE to reset the table (allows to get data and reset in one call)
DT_TABLE_STATS_t *dt_conn_tbl_stats(int reset);

// Find DNS IP enty in the DNS IP table
// Returns a pointer to the IP table entry of NULL if not found
// Call only from the TPCAP thread/handlers
DT_DNS_IP_t *dt_find_dns_ip(IPV4_ADDR_t *ip);

// Start the device telemetry sender (it runs in its own thread)
int dt_sender_start(void);

// DNS info collector init function
int dt_dns_collector_init(void);

// INCOMPLETE: (lmower 20190628)
// This function currently only logs to a file but should be modified
// to collect and ship DHCP table information just as the other collect
// functions do. Rename to dt_dhcp_collector_init() when complete.
// DHCP info collector init function
int dt_dhcp_init(void);

// Device info collector init function
// Returns: 0 - if successful
int dt_main_collector_init(void);

// Subsystem init fuction
int devtelemetry_init(int level);

#ifdef DEBUG
void dt_dns_tbls_test(void);
void dt_if_counters_test(void);
void dt_main_tbls_test(void);
#endif // DEBUG

#endif // _DEVTELEMETRY_COMMON_H

