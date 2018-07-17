/*
 * Copyright (c) 2013, Hasso-Plattner-Institut.
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
 *         AES_128-based CCM* implementation.
 * \author
 *         Original: Konrad Krentz <konrad.krentz@gmail.com>
 *         Generified version: Justin King-Lacroix <justin.kinglacroix@gmail.com>
 */

/*
     Modified for OSCOAP test implementation by: Martin Gunnarsson martin.gunnarsson@sics.se
   */


#include "cose-aes-ccm.h"
#include "lib/aes-128.h"
#include <string.h>
#include "er-oscoap.h"
#include "sys/energest.h"
#include "cc2420.h"


/* see RFC 3610 */
#define CCM_STAR_AUTH_FLAGS(Adata, M) ((Adata ? (1u << 6) : 0) | (((M - 2u) >> 1) << 3) | 7u) //7u for the L' parameter (8 bytes counter)
//#define CCM_STAR_AUTH_FLAGS(Adata, M) ((Adata ? (1u << 6) : 0) | (((M - 2u) >> 1) << 3) | 1u)
#define CCM_STAR_ENCRYPTION_FLAGS     7


static char CBC_flag = 0;


/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

static void
set_iv(uint8_t *iv,
       uint8_t flags,
       const uint8_t *nonce,
       uint8_t counter)
{
   memset(iv, 0x00, AES_128_BLOCK_SIZE);
   iv[0] = flags;
   memcpy(iv + 1, nonce, COSE_AES_CCM_NONCE_LENGTH);
   iv[14] = 0;
   iv[15] = counter;
}

/*---------------------------------------------------------------------------*/
/* XORs the block m[pos] ... m[pos + 15] with K_{counter} */
static void
ctr_step(const uint8_t *nonce,
         uint8_t pos,
         uint8_t *m_and_result,
         uint8_t m_len,
         uint8_t counter)
{
   char energest_type = ENERGEST_TYPE_CTR_ADDITIONAL_SW;

   if (CBC_flag) {
      CBC_flag = 0;
      energest_type = ENERGEST_TYPE_CBC_ADDITIONAL_SW;
   }

   ENERGEST_ON(energest_type);

   uint8_t a[AES_128_BLOCK_SIZE];
   uint8_t i;

   set_iv(a, CCM_STAR_ENCRYPTION_FLAGS, nonce, counter);

   ENERGEST_OFF(energest_type);

   AES_128.encrypt(a);

   ENERGEST_ON(energest_type);

   for (i = 0; (pos + i < m_len) && (i < AES_128_BLOCK_SIZE); i++) {
      m_and_result[pos + i] ^= a[i];
   }

   ENERGEST_OFF(energest_type);

}



/*---------------------------------------------------------------------------*/
static void
mic(const uint8_t *nonce,
    const uint8_t *m, uint8_t m_len,
    const uint8_t *a, uint8_t a_len,
    uint8_t *result,
    uint8_t mic_len)
{
   ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);


   uint8_t x[AES_128_BLOCK_SIZE];
   uint8_t pos;
   uint8_t i;


   set_iv(x, CCM_STAR_AUTH_FLAGS(a_len, mic_len), nonce, m_len);


   /*---------------------------------------------------------------------------*/
   ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
   AES_128.encrypt(a);
   ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
   /*---------------------------------------------------------------------------*/

   if (a_len) {

      x[1] = x[1] ^ a_len;
      for (i = 2; (i - 2 < a_len) && (i < AES_128_BLOCK_SIZE); i++) {
         x[i] ^= a[i - 2];
      }

      /*---------------------------------------------------------------------------*/
      ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
      AES_128.encrypt(a);
      ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
      /*---------------------------------------------------------------------------*/

      pos = 14;
      while (pos < a_len) {

         for (i = 0; (pos + i < a_len) && (i < AES_128_BLOCK_SIZE); i++) {
            x[i] ^= a[pos + i];
         }
         pos += AES_128_BLOCK_SIZE;

         /*---------------------------------------------------------------------------*/
         ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
         AES_128.encrypt(a);
         ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
         /*---------------------------------------------------------------------------*/
      }
   }

   if (m_len) {

      pos = 0;

      while (pos < m_len) {

         for (i = 0; (pos + i < m_len) && (i < AES_128_BLOCK_SIZE); i++) {
            x[i] ^= m[pos + i];
         }
         pos += AES_128_BLOCK_SIZE;

         /*---------------------------------------------------------------------------*/
         ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
         AES_128.encrypt(a);
         ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
         /*---------------------------------------------------------------------------*/
      }
   }


   CBC_flag = 1;

   ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);

   ctr_step(nonce, 0, x, AES_128_BLOCK_SIZE, 0);

   ENERGEST_ON(ENERGEST_TYPE_CBC_ADDITIONAL_SW);
   memcpy(result, x, mic_len);
   ENERGEST_OFF(ENERGEST_TYPE_CBC_ADDITIONAL_SW);

}

/* ---------------------------------------------------------------------------------------------------- */
/* Hardware Implementation of CTR Mode by Rizwan Hamid Randhawa*/
/* To use code comment the code of ctr_step function above and uncomment this code*/
/* ---------------------------------------------------------------------------------------------------- */

// static void ctr_step(const uint8_t *nonce,
//                      uint8_t pos,
//                      uint8_t *m_and_result,
//                      uint8_t m_len,
//                      uint8_t counter)
// {
//    ENERGEST_ON(ENERGEST_TYPE_CTR_HW);
//    uint8_t a[AES_128_BLOCK_SIZE];
//    set_iv(a, CCM_STAR_ENCRYPTION_FLAGS, nonce, counter);
//    AES_128.ctr_cc2420(a, m_and_result);
//    ENERGEST_OFF(ENERGEST_TYPE_CTR_HW);
// }
/*---------------------------------------------------------------------------*/

/* ---------------------------------------------------------------------------------------------------- */
/* Hardware Implementation of CBC-MAC Mode by Rizwan Hamid Randhawa*/
/* To use code comment the code of mic function above and uncomment this code*/
/* ---------------------------------------------------------------------------------------------------- */
// static void mic(const uint8_t *nonce,
//                 const uint8_t *m,
//                 uint8_t m_len,
//                 const uint8_t *a,
//                 uint8_t a_len,
//                 uint8_t *result,
//                 uint8_t mic_len)
// {
//    ENERGEST_ON(ENERGEST_TYPE_CBC_HW);
//    uint8_t x[AES_128_BLOCK_SIZE];
//    set_iv(x, CCM_STAR_AUTH_FLAGS(a_len, mic_len), nonce, m_len);
//    AES_128.cbcmac_cc2420(x, m, m_len, a, a_len, result, mic_len);

//    ENERGEST_OFF(ENERGEST_TYPE_CBC_HW);


//    ctr_step(nonce, 0, x, AES_128_BLOCK_SIZE, 0);


//    ENERGEST_ON(ENERGEST_TYPE_CBC_HW);
//    memcpy(result, x, mic_len);
//    ENERGEST_OFF(ENERGEST_TYPE_CBC_HW);
// }



// /*---------------------------------------------------------------------------*/
static void
ctr(const uint8_t *nonce, uint8_t *m, uint8_t m_len)
{
   ENERGEST_ON(ENERGEST_TYPE_CTR_ADDITIONAL_SW);

   uint8_t pos;
   uint8_t counter;

   pos = 0;
   counter = 1;

   while (pos < m_len) {

      ENERGEST_OFF(ENERGEST_TYPE_CTR_ADDITIONAL_SW);

      ctr_step(nonce, pos, m, m_len, counter++);

      ENERGEST_ON(ENERGEST_TYPE_CTR_ADDITIONAL_SW);
      pos += AES_128_BLOCK_SIZE;
      ENERGEST_OFF(ENERGEST_TYPE_CTR_ADDITIONAL_SW);
   }

   ENERGEST_OFF(ENERGEST_TYPE_CTR_ADDITIONAL_SW);

}

/*---------------------------------------------------------------------------*/
static void
set_key(const uint8_t *key)
{
   AES_128.set_key(key);
}
/*---------------------------------------------------------------------------*/
static void
aead(const uint8_t* nonce,
     uint8_t* m, uint8_t m_len,
     const uint8_t* a, uint8_t a_len,
     uint8_t *result, uint8_t mic_len,
     int forward)
{
   if (!forward) {
      // decrypt
      ctr(nonce, m, m_len);
   }

   mic(nonce,
       m, m_len,
       a, a_len,
       result,
       mic_len);

   if (forward) {

      // encrypt
      ctr(nonce, m, m_len);

   }

}
/*---------------------------------------------------------------------------*/
// static void
// aead(const uint8_t* nonce,
//      uint8_t* m,
//      uint8_t m_len,
//      const uint8_t* a,
//      uint8_t a_len,
//      uint8_t *result,
//      uint8_t mic_len,
//      int forward)
// {
//    ENERGEST_ON(ENERGEST_TYPE_CCM_HW);
//    AES_128.ccm_cc2420(nonce, m, m_len, a, a_len, result, mic_len, forward);
//    ENERGEST_OFF(ENERGEST_TYPE_CCM_HW);


// }
/*---------------------------------------------------------------------------*/
const struct cose_aes_ccm_driver cose_aes_ccm_driver = {
   set_key,
   aead
};
/*---------------------------------------------------------------------------*/
