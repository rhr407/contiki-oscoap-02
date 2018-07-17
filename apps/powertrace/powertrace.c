/*
 * Copyright (c) 2010, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

/**
 * \file
 *         Powertrace: periodically print out power consumption
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "contiki-lib.h"
#include "sys/compower.h"
#include "powertrace.h"
#include "net/rime/rime.h"

#include <stdio.h>
#include <string.h>

struct powertrace_sniff_stats {
   struct powertrace_sniff_stats *next;
   unsigned long num_input, num_output;
   unsigned long input_txtime, input_rxtime;
   unsigned long output_txtime, output_rxtime;
#if NETSTACK_CONF_WITH_IPV6
   uint16_t proto; /* includes proto + possibly flags */
#endif
   uint16_t channel;
   unsigned long last_input_txtime, last_input_rxtime;
   unsigned long last_output_txtime, last_output_rxtime;
};

#define INPUT  1
#define OUTPUT 0

#define MAX_NUM_STATS  16

MEMB(stats_memb, struct powertrace_sniff_stats, MAX_NUM_STATS);
LIST(stats_list);

PROCESS(powertrace_process, "Periodic power output");
/*---------------------------------------------------------------------------*/
void
powertrace_print_mine(char *str)
{
   static unsigned long last_cpu,
          last_lpm,
          last_setKeySW,
          last_encryptSW,
          last_CBC_ADDITIONAL_SW,
          last_CTR_ADDITIONAL_SW,
          last_setKeyHW,
          last_encryptHW,
          last_CBC_HW,
          last_CTR_HW,
          last_CCM_HW,
          last_transmit,
          last_listen;


   static unsigned long cpu,
          lpm,
          setKeySW,
          encryptSW,
          CBC_ADDITIONAL_SW,
          CTR_ADDITIONAL_SW,
          setKeyHW,
          encryptHW,
          CBC_HW,
          CTR_HW,
          CCM_HW,
          transmit,
          listen;

   static unsigned long current_cpu,
          current_lpm,
          current_setKeySW,
          current_encryptSW,
          current_CBC_ADDITIONAL_SW,
          current_CTR_ADDITIONAL_SW,
          current_setKeyHW,
          current_encryptHW,
          current_CBC_HW,
          current_CTR_HW,
          current_CCM_HW,
          current_transmit,
          current_listen;

   static unsigned long seqno;

   energest_flush();

   current_cpu = energest_type_time(ENERGEST_TYPE_CPU);
   current_lpm = energest_type_time(ENERGEST_TYPE_LPM);
   current_setKeySW = energest_type_time(ENERGEST_TYPE_setKeySW);
   current_encryptSW = energest_type_time(ENERGEST_TYPE_encryptSW);
   current_CBC_ADDITIONAL_SW = energest_type_time(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
   current_CTR_ADDITIONAL_SW = energest_type_time(ENERGEST_TYPE_CTR_ADDITIONAL_SW);
   current_setKeyHW = energest_type_time(ENERGEST_TYPE_setKeyHW);
   current_encryptHW = energest_type_time(ENERGEST_TYPE_encryptHW);
   current_CBC_HW = energest_type_time(ENERGEST_TYPE_CBC_HW);
   current_CTR_HW = energest_type_time(ENERGEST_TYPE_CTR_HW);
   current_CCM_HW = energest_type_time(ENERGEST_TYPE_CCM_HW);
   current_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   current_listen = energest_type_time(ENERGEST_TYPE_LISTEN);


   cpu = current_cpu - last_cpu;
   lpm = current_lpm - last_lpm;
   setKeySW = current_setKeySW - last_setKeySW;
   encryptSW = current_encryptSW - last_encryptSW;
   CBC_ADDITIONAL_SW = current_CBC_ADDITIONAL_SW - last_CBC_ADDITIONAL_SW;
   CTR_ADDITIONAL_SW = current_CTR_ADDITIONAL_SW - last_CTR_ADDITIONAL_SW;
   setKeyHW = current_setKeyHW - last_setKeyHW;
   encryptHW = current_encryptHW - last_encryptHW;
   CBC_HW = current_CBC_HW - last_CBC_HW;
   CTR_HW = current_CTR_HW - last_CTR_HW;
   CCM_HW = current_CCM_HW - last_CCM_HW;
   transmit = current_transmit - last_transmit;
   listen = current_listen - last_listen;


   last_cpu = energest_type_time(ENERGEST_TYPE_CPU);
   last_lpm = energest_type_time(ENERGEST_TYPE_LPM);
   last_setKeySW = energest_type_time(ENERGEST_TYPE_setKeySW);
   last_encryptSW = energest_type_time(ENERGEST_TYPE_encryptSW);
   last_CBC_ADDITIONAL_SW = energest_type_time(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
   last_CTR_ADDITIONAL_SW = energest_type_time(ENERGEST_TYPE_CTR_ADDITIONAL_SW);
   last_setKeyHW = energest_type_time(ENERGEST_TYPE_setKeyHW);
   last_encryptHW = energest_type_time(ENERGEST_TYPE_encryptHW);
   last_CBC_HW = energest_type_time(ENERGEST_TYPE_CBC_HW);
   last_CTR_HW = energest_type_time(ENERGEST_TYPE_CTR_HW);
   last_CCM_HW = energest_type_time(ENERGEST_TYPE_CCM_HW);
   last_transmit = energest_type_time(ENERGEST_TYPE_TRANSMIT);
   last_listen = energest_type_time(ENERGEST_TYPE_LISTEN);


   printf("%s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
          str,
          clock_seconds(),
          seqno,
          cpu,
          lpm,
          setKeySW,
          encryptSW,
          CBC_ADDITIONAL_SW,
          CTR_ADDITIONAL_SW,
          setKeyHW,
          encryptHW,
          CBC_HW,
          CTR_HW,
          CCM_HW,
          transmit,
          listen);

   seqno++;
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(powertrace_process, ev, data)
{
   static struct etimer periodic;
   clock_time_t *period;
   PROCESS_BEGIN();

   period = data;

   if (period == NULL) {
      PROCESS_EXIT();
   }
   etimer_set(&periodic, *period);

   while (1) {
      PROCESS_WAIT_UNTIL(etimer_expired(&periodic));
      etimer_reset(&periodic);
      powertrace_print("");
   }

   PROCESS_END();
}
/*---------------------------------------------------------------------------*/
void
powertrace_start(clock_time_t period)
{
   process_start(&powertrace_process, (void *)&period);
}
/*---------------------------------------------------------------------------*/
void
powertrace_stop(void)
{
   process_exit(&powertrace_process);
}
/*---------------------------------------------------------------------------*/
static void
add_stats(struct powertrace_sniff_stats *s, int input_or_output)
{
   if (input_or_output == INPUT) {
      s->num_input++;
      s->input_txtime += packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME);
      s->input_rxtime += packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME);
   } else if (input_or_output == OUTPUT) {
      s->num_output++;
      s->output_txtime += packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME);
      s->output_rxtime += packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME);
   }
}
/*---------------------------------------------------------------------------*/
static void
add_packet_stats(int input_or_output)
{
   struct powertrace_sniff_stats *s;

   /* Go through the list of stats to find one that matches the channel
      of the packet. If we don't find one, we allocate a new one and
      put it on the list. */
   for (s = list_head(stats_list); s != NULL; s = list_item_next(s)) {
      if (s->channel == packetbuf_attr(PACKETBUF_ATTR_CHANNEL)
#if NETSTACK_CONF_WITH_IPV6
            && s->proto == packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID)
#endif
         ) {
         add_stats(s, input_or_output);
         break;
      }
   }
   if (s == NULL) {
      s = memb_alloc(&stats_memb);
      if (s != NULL) {
         memset(s, 0, sizeof(struct powertrace_sniff_stats));
         s->channel = packetbuf_attr(PACKETBUF_ATTR_CHANNEL);
#if NETSTACK_CONF_WITH_IPV6
         s->proto = packetbuf_attr(PACKETBUF_ATTR_NETWORK_ID);
#endif
         list_add(stats_list, s);
         add_stats(s, input_or_output);
      }
   }
}
/*---------------------------------------------------------------------------*/
static void
input_sniffer(void)
{
   add_packet_stats(INPUT);
}
/*---------------------------------------------------------------------------*/
static void
output_sniffer(int mac_status)
{
   add_packet_stats(OUTPUT);
}
/*---------------------------------------------------------------------------*/
#if NETSTACK_CONF_WITH_RIME
static void
sniffprint(char *prefix, int seqno)
{
   const linkaddr_t *esender;
   esender = packetbuf_addr(PACKETBUF_ADDR_ESENDER);

   printf("%lu %s %d %u %d %d %d.%d %u %u\n",
          clock_time(),
          prefix,
          linkaddr_node_addr.u8[0], seqno,
          packetbuf_attr(PACKETBUF_ATTR_CHANNEL),
          packetbuf_attr(PACKETBUF_ATTR_PACKET_TYPE),
          esender->u8[0], esender->u8[1],
          packetbuf_attr(PACKETBUF_ATTR_TRANSMIT_TIME),
          packetbuf_attr(PACKETBUF_ATTR_LISTEN_TIME));
}
/*---------------------------------------------------------------------------*/
static void
input_printsniffer(void)
{
   static int seqno = 0;
   sniffprint("I", seqno++);

   if (packetbuf_attr(PACKETBUF_ATTR_CHANNEL) == 0) {
      int i;
      uint8_t *dataptr;

      printf("x %d ", packetbuf_totlen());
      dataptr = packetbuf_hdrptr();
      printf("%02x ", dataptr[0]);
      for (i = 1; i < packetbuf_totlen(); ++i) {
         printf("%02x ", dataptr[i]);
      }
      printf("\n");
   }
}
/*---------------------------------------------------------------------------*/
static void
output_printsniffer(int mac_status)
{
   static int seqno = 0;
   sniffprint("O", seqno++);
}
/*---------------------------------------------------------------------------*/
RIME_SNIFFER(printsniff, input_printsniffer, output_printsniffer);
/*---------------------------------------------------------------------------*/
void
powertrace_printsniff(powertrace_onoff_t onoff)
{
   switch (onoff) {
   case POWERTRACE_ON:
      rime_sniffer_add(&printsniff);
      break;
   case POWERTRACE_OFF:
      rime_sniffer_remove(&printsniff);
      break;
   }
}
#endif /* NETSTACK_CONF_WITH_RIME */
/*---------------------------------------------------------------------------*/
RIME_SNIFFER(powersniff, input_sniffer, output_sniffer);
/*---------------------------------------------------------------------------*/
void
powertrace_sniff(powertrace_onoff_t onoff)
{
   switch (onoff) {
   case POWERTRACE_ON:
      rime_sniffer_add(&powersniff);
      break;
   case POWERTRACE_OFF:
      rime_sniffer_remove(&powersniff);
      break;
   }
}
