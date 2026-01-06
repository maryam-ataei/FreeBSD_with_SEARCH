/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
 *	The Regents of the University of California.
 * Copyright (c) 2007-2008,2010,2014
 *	Swinburne University of Technology, Melbourne, Australia.
 * Copyright (c) 2009-2010 Lawrence Stewart <lstewart@freebsd.org>
 * Copyright (c) 2010 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed at the Centre for Advanced Internet
 * Architectures, Swinburne University of Technology, by Lawrence Stewart, James
 * Healy and David Hayes, made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 *
 * Portions of this software were developed at the Centre for Advanced
 * Internet Architectures, Swinburne University of Technology, Melbourne,
 * Australia by David Hayes under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * This software was first released in 2007 by James Healy and Lawrence Stewart
 * whilst working on the NewTCP research project at Swinburne University of
 * Technology's Centre for Advanced Internet Architectures, Melbourne,
 * Australia, which was made possible in part by a grant from the Cisco
 * University Research Program Fund at Community Foundation Silicon Valley.
 * More details are available at:
 *   http://caia.swin.edu.au/urp/newtcp/
 *
 * Dec 2014 garmitage@swin.edu.au
 * Borrowed code fragments from cc_cdg.c to add modifiable beta
 * via sysctls.
 *
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/vnet.h>

#include <net/route.h>
#include <net/route/nhop.h>

#include <netinet/in_pcb.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_log_buf.h>
#include <netinet/tcp_hpts.h>
#include <netinet/cc/cc.h>
#include <netinet/cc/cc_module.h>
#include <sys/syslog.h>
/* SEARCH_begin */
#include <netinet/cc/cc_newreno_search.h>
#include <sys/khelp.h>
#include <netinet/khelp/h_ertt.h>
#include <sys/time.h>
#include <netinet/tcp_hpts.h>
/* SEARCH_end */

/*
 * SEARCH: Logging and debug macros
 */
#define SEARCH_LOG_ENABLED
#define HYSTARTPP_LOG_ENABLED
#define ACK_LOG_ENABLED
#define DEBUG_LOG_ENABLED

static void	newreno_cb_destroy(struct cc_var *ccv);
static void	newreno_ack_received(struct cc_var *ccv, uint16_t type);
static void	newreno_after_idle(struct cc_var *ccv);
static void	newreno_cong_signal(struct cc_var *ccv, uint32_t type);
static int newreno_ctl_output(struct cc_var *ccv, struct sockopt *sopt, void *buf);
static void	newreno_newround(struct cc_var *ccv, uint32_t round_cnt);
static void	newreno_rttsample(struct cc_var *ccv, uint32_t usec_rtt, uint32_t rxtcnt, uint32_t fas);
static 	int	newreno_cb_init(struct cc_var *ccv, void *);
static size_t	newreno_data_sz(void);


VNET_DECLARE(uint32_t, newreno_beta);
#define V_newreno_beta VNET(newreno_beta)
VNET_DECLARE(uint32_t, newreno_beta_ecn);
#define V_newreno_beta_ecn VNET(newreno_beta_ecn)

/* SEARCH_begin */
/*
 * SEARCH: Congestion control algorithm registration.
 *
 * Defines the NewReno variant with integrated SEARCH support.
 * Registered as "newreno_search" to the FreeBSD CC framework.
 */
struct cc_algo newreno_search_cc_algo = {
	.name = "newreno_search", 
	/* SEARCH_end */
	.cb_destroy = newreno_cb_destroy,
	.ack_received = newreno_ack_received,
	.after_idle = newreno_after_idle,
	.cong_signal = newreno_cong_signal,
	.post_recovery = newreno_cc_post_recovery,
	.ctl_output = newreno_ctl_output,
	.newround = newreno_newround,
	.rttsample = newreno_rttsample,
	.cb_init = newreno_cb_init,
	.cc_data_sz = newreno_data_sz,
};
 

/* SEARCH_begin */
/*
 * SEARCH: Reset state and measurement bins.
 *
 * Clears all delivered and sent byte bins, resets counters,
 * and optionally clears the bin duration (when requested).
 * Used on connection init or after major time gaps between bins.
 */
static void search_reset(struct newreno* nreno, enum unset_bin_duration flag) {
	memset(nreno->search_acked_bin, 0, sizeof(nreno->search_acked_bin));
	memset(nreno->search_sent_bin, 0, sizeof(nreno->search_sent_bin));
	nreno->search_curr_idx = -1;
	nreno->search_bin_end_us = 0;
	nreno->search_scale_factor = 0;
	nreno->search_targeted_cwnd = 0;			// NEW_CHANGE
	nreno->search_snd_max_prev = 0;				// NEW_CHANGE
	nreno->search_cwnd_reduction_target = 0;	// NEW_CHANGE 
	nreno->search_drain_k = 0;					// NEW_CHANGE
	nreno->search_drain_acked_segs = 0;			// NEW_CHANGE
	if (flag == RESET_BIN_DURATION_TRUE)
		nreno->search_bin_duration_us = 0;
}

/*
 * SEARCH: Get current time in microseconds.
 *
 * Wrapper around tcp_get_usecs() that returns a 64-bit timestamp.
 * Prevents overflow caused by 32-bit microsecond counters by
 * combining seconds and microseconds explicitly.
 */
static inline uint64_t
get_now_us(void)
{
    struct timeval tv;
    tcp_get_usecs(&tv);
    /* 
    * NOTE: Be careful with overflow here!
    * If tcp_get_usecs() returns a 32-bit microsecond counter, it will wrap
    * around every ~71 minutes (2^32 µs). That’s why logs may show `now`
    * jumping from ~4,294,966,xxx back to a small number.
    * Using a 64-bit calculation (tv_sec * 1e6 + tv_usec) avoids this issue.
    */
    return ((uint64_t)tv.tv_sec * 1000000ULL) + tv.tv_usec;
}
/* SEARCH_end */

static void
newreno_log_hystart_event(struct cc_var *ccv, struct newreno *nreno, uint8_t mod, uint32_t flex1)
{
	/*
	 * Types of logs (mod value)
	 * 1 - rtt_thresh in flex1, checking to see if RTT is to great.
	 * 2 - rtt is too great, rtt_thresh in flex1.
	 * 3 - CSS is active incr in flex1
	 * 4 - A new round is beginning flex1 is round count
	 * 5 - A new RTT measurement flex1 is the new measurement.
	 * 6 - We enter CA ssthresh is also in flex1.
	 * 7 - Socket option to change hystart executed opt.val in flex1.
	 * 8 - Back out of CSS into SS, flex1 is the css_baseline_minrtt
	 * 9 - We enter CA, via an ECN mark.
	 * 10 - We enter CA, via a loss.
	 * 11 - We have slipped out of SS into CA via cwnd growth.
	 * 12 - After idle has re-enabled hystart++
	 */
	struct tcpcb *tp;

	if (hystart_bblogs == 0)
		return;
	tp = ccv->ccvc.tcp;
	if (tcp_bblogging_on(tp)) {
		union tcp_log_stackspecific log;
		struct timeval tv;

		memset(&log, 0, sizeof(log));
		log.u_bbr.flex1 = flex1;
		log.u_bbr.flex2 = nreno->css_current_round_minrtt;
		log.u_bbr.flex3 = nreno->css_lastround_minrtt;
		log.u_bbr.flex4 = nreno->css_rttsample_count;
		log.u_bbr.flex5 = nreno->css_entered_at_round;
		log.u_bbr.flex6 = nreno->css_baseline_minrtt;
		/* We only need bottom 16 bits of flags */
		log.u_bbr.flex7 = nreno->newreno_flags & 0x0000ffff;
		log.u_bbr.flex8 = mod;
		log.u_bbr.epoch = nreno->css_current_round;
		log.u_bbr.timeStamp = tcp_get_usecs(&tv);
		log.u_bbr.lt_epoch = nreno->css_fas_at_css_entry;
		log.u_bbr.pkts_out = nreno->css_last_fas;
		log.u_bbr.delivered = nreno->css_lowrtt_fas;
		log.u_bbr.pkt_epoch = ccv->flags;
		TCP_LOG_EVENTP(tp, NULL,
		    &tptosocket(tp)->so_rcv,
		    &tptosocket(tp)->so_snd,
		    TCP_HYSTART, 0,
		    0, &log, false, &tv);
	}
}

static size_t
newreno_data_sz(void)
{
	return (sizeof(struct newreno));
}

static int
newreno_cb_init(struct cc_var *ccv, void *ptr)
{
	struct newreno *nreno;

	INP_WLOCK_ASSERT(tptoinpcb(ccv->ccvc.tcp));
	if (ptr == NULL) {
		ccv->cc_data = malloc(sizeof(struct newreno), M_CC_MEM, M_NOWAIT);
		if (ccv->cc_data == NULL)
			return (ENOMEM);
	} else
		ccv->cc_data = ptr;
	nreno = (struct newreno *)ccv->cc_data;
	/* NB: nreno is not zeroed, so initialise all fields. */
	nreno->beta = V_newreno_beta;
	nreno->beta_ecn = V_newreno_beta_ecn;
	/*
	 * We set the enabled flag so that if
	 * the socket option gets strobed and
	 * we have not hit a loss
	 */
	nreno->newreno_flags = CC_NEWRENO_HYSTART_ENABLED;
	/* At init set both to infinity */
	nreno->css_lastround_minrtt = 0xffffffff;
	nreno->css_current_round_minrtt = 0xffffffff;
	nreno->css_current_round = 0;
	nreno->css_baseline_minrtt = 0xffffffff;
	nreno->css_rttsample_count = 0;
	nreno->css_entered_at_round = 0;
	nreno->css_fas_at_css_entry = 0;
	nreno->css_lowrtt_fas = 0;
	nreno->css_last_fas = 0;
	/* SEARCH_begin */
	nreno->last_rtt_sample = 0;
	nreno->search_cumulative_acked_bytes = 0;
	if (V_use_search){
		search_reset(nreno, RESET_BIN_DURATION_TRUE);
	}
	#if defined(ACK_LOG_ENABLED)
	log(LOG_INFO, "<%p> ACK:[CCRG]Connection initiated [now %lu] [initial_cwnd %u] [initial_ssthresh %u]\n", 
	ccv, get_now_us(), CCV(ccv, snd_cwnd), CCV(ccv, snd_ssthresh)); 
	#endif
	/* SEARCH_end */
	return (0);
}

static void
newreno_cb_destroy(struct cc_var *ccv)
{
	free(ccv->cc_data, M_CC_MEM);
}

/* SEARCH_begin */
/*
 * SEARCH: Retrieve smoothed RTT (srtt) in microseconds.
 *
 * Converts t_srtt (stored in fixed-point ticks) to us using TCP_RTT_SHIFT.
 * Used when the ERTT helper is unavailable.
 */
static uint64_t 
get_srtt_us(struct cc_var* ccv) {
	uint64_t srtt = CCV(ccv, t_srtt);
	return (((uint64_t)srtt) * tick) >> TCP_RTT_SHIFT;  // convert to microseconds
}
 
/*
 * SEARCH: Dynamic scaling to prevent overflow.
 *
 * Right-shifts all SEARCH bins (acked and sent) if any bin value exceeds MAX_US_INT.
 * This ensures bin values stay within safe range while maintaining proportionality.
 */
static uint8_t 
search_bit_shifting(struct cc_var* ccv, uint64_t bin_value) {

	struct newreno* nreno = ccv->cc_data;
	uint8_t num_shift = 0;	
	int i;

	/* Determine required shift count to fit into bin size */
	while (bin_value > MAX_US_INT) {
		num_shift+= 1;
		bin_value >>= 1;
	}

	if (num_shift == 0)
    	return 0;

	/* Adjust all previous acked bins according to the new shift amount */
	for (i = 0; i < SEARCH_ACKED_BINS; i++) {
		SEARCH_ACKED_BIN(ccv, i) >>= num_shift;
	}

	/* Adjust all previous sent bins according to the new shift amount */
	for (i = 0; i < SEARCH_SENT_BINS; i++) {
		SEARCH_SENT_BIN(ccv, i) >>= num_shift;
	}

	/* Update shared scale factor */
	nreno->search_scale_factor += num_shift;

	return num_shift;
}

/*
 * SEARCH: Initialize measurement bins.
 *
 * Called on first ACK reception to establish the SEARCH window structure.
 * Sets bin duration, end timestamp, and populates the first bin with
 * cumulative acked and sent bytes (scaled if necessary).
 */
static void 
search_init_bins(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {

	struct newreno* nreno = ccv->cc_data;
	uint8_t amount_scaled = 0;
	uint64_t acked_val = 0;
	uint64_t sent_val = 0;
	uint64_t largest_val = 0;

	if (nreno->search_bin_duration_us == 0)
		// Window duration: proportional to RTT × window size factor
		nreno->search_bin_duration_us = (rtt_us * SEARCH_WINDOW_SIZE_FACTOR) / (SEARCH_WIN_BINS * 10);

	nreno->search_bin_end_us = now_us + nreno->search_bin_duration_us;
	nreno->search_curr_idx = 0;

	acked_val = nreno->search_cumulative_acked_bytes;	/* cumulative acked bytes */
	sent_val = CCV(ccv, t_sndbytes);    				/* total bytes sent */

	/* 
	 * Prevent bin overflow by right-shifting both acked and sent values
	 * proportionally if either exceeds MAX_US_INT. This ensures consistent scaling
	 * across arrays.
	 */
	if (acked_val > MAX_US_INT || sent_val > MAX_US_INT) {
		largest_val = (acked_val > sent_val) ? acked_val : sent_val;
		amount_scaled = search_bit_shifting(ccv, largest_val);
		acked_val >>= amount_scaled;
		sent_val  >>= amount_scaled;
	}

	nreno->search_acked_bin[0] = (search_bin_t)acked_val;
	nreno->search_sent_bin[0]  = (search_bin_t)sent_val;
}
 
/*
 * SEARCH: Advance bin windows and maintain temporal continuity.
 *
 * Updates bin arrays as time progresses:
 *  - Computes the number of passed bins since the last update.
 *  - Resets bins if too much time has elapsed (missed bins).
 *  - Filled intermediate bins with last known value when multiple bins have passed.
 *  - Applies dynamic scaling to prevent overflow.
 */
static void 
search_update_bins(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {

	struct newreno* nreno = ccv->cc_data;

	uint32_t passed_bins = 0;
	uint64_t acked_val = 0; 
	uint64_t sent_val = 0;
	uint8_t amount_scaled = 0; 
	uint64_t initial_rtt = 0;
	uint64_t largest_val = 0; 
	int i; 

	/* If passed_bins greater than 1, it means we have some missed bins */
	passed_bins = ((now_us - nreno->search_bin_end_us) / nreno->search_bin_duration_us) + 1;

	initial_rtt = nreno->search_bin_duration_us * SEARCH_WIN_BINS * 10 / SEARCH_WINDOW_SIZE_FACTOR;

	#if defined(SEARCH_LOG_ENABLED)
	log(LOG_INFO, "<%p> SEARCH:[CCRG] [now %lu] Update bins: [passed_bins %d] [initial_rtt %lu]\n", 
	ccv, now_us, passed_bins, initial_rtt);
	#endif

	/* Need reset due to missed bins */
	if (passed_bins > SEARCH_ALPHA * (initial_rtt / nreno->search_bin_duration_us)) {

		if (passed_bins > SEARCH_WIN_BINS) {
			search_reset(nreno, RESET_BIN_DURATION_TRUE);
		}
		else {
			search_reset(nreno, RESET_BIN_DURATION_FALSE);

		}
		
		log(LOG_INFO, "<%p> DEBUG:[CCRG] [now %lu] SEARCH reset due to the missed bins\n",
		ccv, now_us);

		search_init_bins(ccv, now_us, rtt_us);
		return;
	}

	// Recreate continuity by copying last known values into missed bins
	for (i = nreno->search_curr_idx + 1; i < nreno->search_curr_idx + passed_bins; i++) {

		SEARCH_ACKED_BIN(ccv, i) = SEARCH_ACKED_BIN(ccv, nreno->search_curr_idx);
		SEARCH_SENT_BIN(ccv, i)  = SEARCH_SENT_BIN(ccv, nreno->search_curr_idx);
	}

	nreno->search_curr_idx += passed_bins;
	nreno->search_bin_end_us += passed_bins * nreno->search_bin_duration_us;

	/* Calculate bin_value by dividing bytes by 2^scale_factor */
	acked_val = nreno->search_cumulative_acked_bytes >> nreno->search_scale_factor;
	sent_val  = CCV(ccv, t_sndbytes) >> nreno->search_scale_factor;

	if (acked_val > MAX_US_INT || sent_val > MAX_US_INT) {
		largest_val = (acked_val > sent_val) ? acked_val : sent_val;
		amount_scaled = search_bit_shifting(ccv, largest_val);
		acked_val >>= amount_scaled;
		sent_val  >>= amount_scaled;
	}

	SEARCH_ACKED_BIN(ccv, nreno->search_curr_idx) = (search_bin_t)acked_val;
	SEARCH_SENT_BIN(ccv,  nreno->search_curr_idx) = (search_bin_t)sent_val;

	#if defined(SEARCH_LOG_ENABLED)
	log(LOG_INFO, " SEARCH:[CCRG] SEARCH SENT BINS: " );
	for (int i = 0; i < SEARCH_SENT_BINS; i++) {
		log(LOG_INFO, "| %u ", nreno->search_sent_bin[i]);
	}
	log(LOG_INFO, "|\n");
	#endif

	#if defined(SEARCH_LOG_ENABLED)
	log(LOG_INFO, "SEARCH:[CCRG] SEARCH ACKED BINS: ");
	for (int i = 0; i < SEARCH_ACKED_BINS; i++) {
		log(LOG_INFO, "| %u ", nreno->search_acked_bin[i]);
	}
	log(LOG_INFO, "|\n");
	#endif
}

/*
 * SEARCH: Compute sent window integral with fractional interpolation.
 *
 * Calculates the cumulative bytes within [left, right] indices for
 * the SENT window. Adds fractional contributions
 * for partial bin edges using linear interpolation.
 *
 * Arguments:
 *  - left, right: window bounds (bin indices)
 *  - fraction: percentage (0–100) for fractional coverage at edges
 */
static inline uint64_t
search_compute_sent_window(struct cc_var *ccv, int32_t left, int32_t right, uint32_t fraction) {

    uint64_t w = 0;

    w  = SEARCH_SENT_BIN(ccv, right - 1) - SEARCH_SENT_BIN(ccv, left);

    if (left == 0) {
        w += SEARCH_SENT_BIN(ccv, left) * fraction / 100;
    } else {
        w += (SEARCH_SENT_BIN(ccv, left) - SEARCH_SENT_BIN(ccv, left - 1)) * fraction / 100;
    }

    w += (SEARCH_SENT_BIN(ccv, right) - SEARCH_SENT_BIN(ccv, right - 1)) * (100 - fraction) / 100;
    
    return w;
}

/*
 * SEARCH: Compute delv window integral with fractional interpolation.
 *
 * Calculates the cumulative sent bytes within [left, right] indices for
 * the ACKed window. 
 *
 * Arguments:
 *  - left, right: window bounds (bin indices)
 */
static inline uint64_t
search_compute_delv_window(struct cc_var *ccv, int32_t left, int32_t right) {

    uint64_t w = 0;

    w = SEARCH_ACKED_BIN(ccv, right) - SEARCH_ACKED_BIN(ccv, left);

    return w;
}

// NEW_CHANGE
static void 
search_compute_target_cwnd(struct cc_var* ccv, uint64_t now_us, uint64_t rtt_us) {
	struct newreno* nreno = ccv->cc_data;

	int32_t cong_idx = 0;
	uint32_t overshoot_cwnd = 0;
	uint32_t overshoot_cwnd_rescaled = 0;
	
	/*
	* If cwnd rollback is enabled, the code calculates the current round-trip time (RTT)
	* and determines the congestion index (`cong_idx`) from which to compute the overshoot.
	* The overshoot represents the excess bytes delivered beyond the estimated target,
	* which is calculated over a window defined by the current and the rollback indices.
	* 
	* The rollback logic adjusts the congestion window (`snd_cwnd`) based on the overshoot:
	* 1. It first computes the overshoot congestion window (`overshoot_cwnd`), derived by
	*    dividing the overshoot bytes by the maximum segment size (MSS).
	* 2. It reduces `snd_cwnd` by the calculated overshoot while ensuring it does not fall
	*    below the initial congestion window (`TCP_INIT_CWND`), which acts as a safety guard.
	* 3. If the overshoot exceeds the current congestion window, it resets `snd_cwnd` to the 
	*    initial value, providing a safeguard to avoid a drastic drop in case of miscalculations
	*    or unusual network conditions (e.g., TCP reset).
	* 
	* After adjusting the congestion window, the slow start threshold (`snd_ssthresh`) is set 
	* to the updated congestion window to finalize the rollback.
	*/

	if (V_CWND_ROLLBACK) {

		cong_idx = nreno->search_curr_idx - ((17 * rtt_us / 10) / nreno->search_bin_duration_us);

		if (nreno->search_curr_idx - cong_idx <= SEARCH_ACKED_BINS - 1){

			/* Calculate the overshoot based on the delivered bytes between cong_idx and the current index */
			overshoot_cwnd = (int64_t)search_compute_delv_window(ccv, cong_idx, nreno->search_curr_idx);

			overshoot_cwnd_rescaled = overshoot_cwnd << nreno->search_scale_factor;

			//nreno->search_targeted_cwnd = max(CCV(ccv, snd_cwnd) - overshoot_cwnd_rescaled, V_tcp_initcwnd_segments);
			nreno->search_targeted_cwnd = 1000000;

			log(LOG_INFO, "<%p> SEARCH:[CCRG] [now %lu] [curr_cwnd %u] [overshoot_cwnd %u] [overshoot_cwnd_rescaled %u]" 
				" [cong_idx %u] [updated_cwnd %u] [search_targeted_cwnd %lu]\n", 
				ccv,
				now_us, 
				CCV(ccv, snd_cwnd), 
				overshoot_cwnd,
				overshoot_cwnd_rescaled,
				cong_idx,
				max(CCV(ccv, snd_cwnd) - overshoot_cwnd_rescaled, V_tcp_initcwnd_segments),
				nreno->search_targeted_cwnd);
		}
		else 
			log(LOG_INFO, "<%p> SEARCH:[CCRG] [now %lu] cong_idx is too small for rollback [cong_idx %u] \n", ccv, now_us, cong_idx); 
	}
}

/*
 * SEARCH: Log instantaneous exit rates.
 *
 * Calculates per-RTT throughput (bytes/sec) for both sent and ACKed data
 * to provide diagnostic insight into the exit decision conditions.
 *
 * Only used for debugging and analysis during SEARCH slow-start exit.
 */
static void 
search_log_exit_rate(struct cc_var *ccv,
                    struct newreno *nreno,
                    int32_t prev_idx,
                    uint64_t now_us,
                    uint64_t rtt_us)
{
	//#if defined(SEARCH_LOG_ENABLED)
	uint64_t delta_acked_bytes_for_rtt = 0;
	uint64_t delta_sent_bytes_for_rtt = 0;
	uint64_t b_acked_per_sec_per_rtt = 0;
	uint64_t b_sent_per_sec_per_rtt = 0;

	if (rtt_us == 0) 
		return;
	
	if (SEARCH_ACKED_BIN(ccv, nreno->search_curr_idx) > SEARCH_ACKED_BIN(ccv, prev_idx))
		delta_acked_bytes_for_rtt = SEARCH_ACKED_BIN(ccv, nreno->search_curr_idx) - SEARCH_ACKED_BIN(ccv, prev_idx);

	b_acked_per_sec_per_rtt = (delta_acked_bytes_for_rtt * 8ULL * 1000000ULL) / rtt_us;  /* b/s */

	if (SEARCH_SENT_BIN(ccv, nreno->search_curr_idx) > SEARCH_SENT_BIN(ccv, prev_idx))
		delta_sent_bytes_for_rtt = SEARCH_SENT_BIN(ccv, nreno->search_curr_idx) - SEARCH_SENT_BIN(ccv, prev_idx);

	b_sent_per_sec_per_rtt = (delta_sent_bytes_for_rtt * 8ULL * 1000000ULL) / rtt_us;  /* b/s */

	log(LOG_INFO, "<%p> SEARCH:[CCRG] SEARCH_EXIT_RATE: "
    "[now %lu] [delta_sent_bytes_for_rtt %lu] [delta_acked_bytes_for_rtt %lu] [rtt_us %lu] "
    "[rate_sent_per_rtt %lu] [rate_acked_per_rtt %lu b/s]\n",
    ccv,
    now_us,
    delta_sent_bytes_for_rtt,
    delta_acked_bytes_for_rtt,
    rtt_us,
    b_sent_per_sec_per_rtt,
    b_acked_per_sec_per_rtt);
	//#endif
}

/*
 * SEARCH: Main update routine.
 *
 * Periodically called on ACK events to:
 *  1. Initialize bins if not yet active.
 *  2. Advance bins once the current bin boundary passes.
 *  3. Compare delivered and sent windows over one RTT to detect
 *     throughput degradation (SEARCH exit condition).
 *
 * Returns:
 *  - true  -> if slow start exit condition is triggered
 *  - false -> otherwise (continue probing)
 *
 * Notes:
 *  - Uses normalized difference (norm_diff) between delivered and sent bytes
 *    to determine slowdown. Exits slow start when norm_diff exceeds SEARCH_THRESH.
 */

static bool 
search_update(struct cc_var* ccv, int64_t now_us, int64_t rtt_us) {

	struct newreno* nreno = ccv->cc_data;

	int32_t prev_idx = 0;
	int64_t curr_delv_bytes = 0;	
	int64_t prev_sent_bytes = 0;	
	int32_t norm_diff = 0; 
	uint32_t fraction = 0;
	uint32_t inflight = 0;	// NEW_CHANGE
	uint32_t mss = 0;		// NEW_CHANGE
	uint32_t real_inflight = 0;
	u_int i;
	uint32_t new_cwnd = 0;

	mss = tcp_fixed_maxseg(ccv->ccvc.tcp);	// NEW_CHANGE

	if (CCV(ccv, snd_cwnd) > CCV(ccv, snd_ssthresh))
    	return false;

	if (nreno->search_cwnd_reduction_target == 0) { // NEW_CHANGE

		nreno->search_snd_max_prev = CCV(ccv, snd_max); // NEW_CHANGE

		/* by receiving the first ack packet, initialize bin duration and bin end time */
		if (nreno->search_curr_idx < 0) {
			search_init_bins(ccv, now_us, rtt_us);
			return false;
		}

		// Wait until reaching the bin boundary,
		if (now_us < nreno->search_bin_end_us) {
			return false;
		}

		search_update_bins(ccv, now_us, rtt_us);

		/* check if there are enough bins after the shift for computing the sent window */
		prev_idx = nreno->search_curr_idx - (rtt_us / nreno->search_bin_duration_us);

		/* Need enough history to compute windows:
		 * - current window: last SEARCH_ACKED_BIN (acked array)
		 * - previous window: ends at prev_idx, length SEARCH_ACKED_BIN (sent array)
		*/
		if (prev_idx >= SEARCH_WIN_BINS && (nreno->search_curr_idx - prev_idx) < (SEARCH_EXTRA_SENT_BINS - 1)) {
			
			curr_delv_bytes = (int64_t)search_compute_delv_window(
				ccv,
				nreno->search_curr_idx - SEARCH_WIN_BINS,
				nreno->search_curr_idx);

			fraction = ((rtt_us % nreno->search_bin_duration_us) * 100 / nreno -> search_bin_duration_us);

			prev_sent_bytes = (int64_t)search_compute_sent_window(
				ccv,
				prev_idx - SEARCH_WIN_BINS,
				prev_idx,
				fraction);

			if (prev_sent_bytes > 0) {
				norm_diff = (prev_sent_bytes - curr_delv_bytes) * 100 / prev_sent_bytes;

				/* check for exit condition */
				if (prev_sent_bytes >= curr_delv_bytes && norm_diff >= SEARCH_THRESH) {

					#if defined(SEARCH_LOG_ENABLED)
					log(LOG_INFO, "<%p> SEARCH:[CCRG] [now %lu] [bin_duration %d] "
						"[bin_end %lu] [curr_delv %ld] [prev_sent %ld] [norm_100 %d] "
						"[scale_factor %d] [curr_idx %d] [prev_idx %d] [fraction %u]\n",
						ccv,
						now_us, 
						nreno->search_bin_duration_us, 
						nreno->search_bin_end_us, 
						curr_delv_bytes,
						prev_sent_bytes,
						norm_diff,
						nreno->search_scale_factor,
						nreno->search_curr_idx,
						prev_idx,
						fraction
						);
					#endif

					// NEW_CHANGE
					/* Enter SEARCH drain instead of hard exit */
					nreno->search_cwnd_reduction_target = 1;
					/* Compute target cwnd but do NOT apply it yet */
					search_compute_target_cwnd(ccv, now_us, rtt_us);
					return true;
				}
			}
		}
	}

	else {

		if (SEQ_GT(nreno->search_snd_max_prev, CCV(ccv, snd_una))) {
		inflight = (uint32_t)SEQ_SUB(nreno->search_snd_max_prev, CCV(ccv, snd_una));


		if (SEQ_GEQ(CCV(ccv, snd_max), CCV(ccv, snd_una)))
    		real_inflight = (uint32_t)SEQ_SUB(CCV(ccv, snd_max), CCV(ccv, snd_una));
    	else {
    		real_inflight = 0;
    	}

		log(LOG_INFO,
			"<%p> SEARCH:[CCRG] IN_DRAIN [now %lu] [inflight %u] [cwnd_before %u] [target %lu] [pre_snd_max %u] [snd_max %u] [snd_una %u]\n",
			ccv, now_us, inflight, CCV(ccv, snd_cwnd), nreno->search_targeted_cwnd, nreno->search_snd_max_prev, CCV(ccv, snd_max), CCV(ccv, snd_una));

		nreno->search_snd_max_prev = CCV(ccv, snd_max);

		if (nreno->search_drain_k == 0) 
			nreno->search_drain_k = 4;

		if (nreno->search_drain_acked_segs < nreno->search_drain_k) {

			i = ccv->bytes_this_ack / mss;

			nreno->search_drain_acked_segs += i;

			new_cwnd = real_inflight;

		}

		else {
			/* allow limited replacement sending */
			new_cwnd = inflight;
			i = 0;
		}


		/* Force cwnd to inflight or target cwnd, never go below target while draining */
		CCV(ccv, snd_cwnd) = max((uint32_t)new_cwnd, (uint32_t)nreno->search_targeted_cwnd);

		log(LOG_INFO,
			"<%p> SEARCH:[CCRG] DRAIN_APPLIED [now %lu] [inflight %u] [cwnd %u] [pre_snd_max %u]\n",
			ccv, now_us, inflight, CCV(ccv, snd_cwnd), nreno->search_snd_max_prev);
		
		/* Check if drain completed */
		if (CCV(ccv, snd_cwnd) == (uint32_t)nreno->search_targeted_cwnd) {

			search_log_exit_rate(ccv, nreno,
				prev_idx,
				now_us,
				rtt_us);

			CCV(ccv, snd_cwnd) = nreno->search_targeted_cwnd;
			CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd);

	        /* Fully exit SEARCH */
	        search_reset(nreno, RESET_BIN_DURATION_TRUE);

	        //#if defined(SEARCH_LOG_ENABLED)
			log(LOG_INFO, "<%p> SEARCH:[CCRG] [now %lu] [exit condition was met [cwnd %u] [ssthresh %u]\n", 
		 		ccv,
				now_us, 
				CCV(ccv, snd_cwnd), 
				CCV(ccv, snd_ssthresh));
			//#endif
	    }
	    
	    return true;
	}

	#if defined(SEARCH_LOG_ENABLED)
	log(LOG_INFO, "<%p> SEARCH:[CCRG][now %lu] [bin_duration %d] "
		"[bin_end %lu] [curr_delv %ld] [prev_sent %ld] [norm_100 %d] "
		"[scale_factor %d] [curr_idx %d] [prev_idx %d] [fraction %u] [in_flight %u]\n",
		ccv,
		now_us, 
		nreno->search_bin_duration_us, 
		nreno->search_bin_end_us, 
		curr_delv_bytes,
		prev_sent_bytes,
		norm_diff,
		nreno->search_scale_factor,
		nreno->search_curr_idx,
		prev_idx,
		fraction,
		inflight
		);
	#endif

	return false;
}
/* SEARCH_end */

static void
newreno_ack_received(struct cc_var *ccv, uint16_t type)
{
	struct newreno *nreno;
	
	nreno = ccv->cc_data;

	/* SEARCH_begin */
	uint64_t now_us = 0;
	uint64_t rtt_us = 0;
	uint32_t infl_dbg = 0;

	now_us = get_now_us();

	if (nreno->last_rtt_sample > 0){
		rtt_us = nreno->last_rtt_sample;
	} else
		rtt_us = get_srtt_us(ccv);

	// Update cumulative delivered bytes for SEARCH analysis
	nreno->search_cumulative_acked_bytes += ccv->bytes_this_ack; 
	/* SEARCH_end */

	#if defined(ACK_LOG_ENABLED)
	log(LOG_INFO, "<%p> ACK:[CCRG] [now %lu] [rtt_us %lu] [cur_bytes %u] [curack %u]  [cwnd %u] [ssthresh %u]\n",
        ccv,
        now_us,
        rtt_us,
        ccv->bytes_this_ack,
        ccv->curack,
        CCV(ccv, snd_cwnd),
        CCV(ccv, snd_ssthresh)
        );

	log(LOG_INFO, "<%p> ACK:[CCRG] [mss %u] [total_bytes_acked %u] [total_bytes_sent %lu] [cwnd_limited %d]\n",
        ccv,
        CCV(ccv, t_maxseg),
        nreno->search_cumulative_acked_bytes,
        CCV(ccv, t_sndbytes),
        (ccv->flags & CCF_CWND_LIMITED) ? 1 : 0
        );
  	#endif

	#if defined(DEBUG_LOG_ENABLED)
	if (SEQ_GEQ(CCV(ccv, snd_max), CCV(ccv, snd_una)))
    	infl_dbg = (uint32_t)SEQ_SUB(CCV(ccv, snd_max), CCV(ccv, snd_una));
	uint32_t cwnd = CCV(ccv, snd_cwnd);
	uint32_t rwnd = CCV(ccv, rcv_wnd);
	uint32_t snwd = CCV(ccv, snd_wnd);

	log(LOG_INFO, "<%p> DEBUG:[CCRG] [cwnd %u] [in_ackreceived_inflight %u] [rwnd %u] [snwd %u] [snd_max %u] [snd_una %u]\n",
           ccv, cwnd, infl_dbg, rwnd, snwd, CCV(ccv, snd_max), CCV(ccv, snd_una));
	#endif
	
	if (type == CC_ACK && !IN_RECOVERY(CCV(ccv, t_flags)) &&
	    (ccv->flags & CCF_CWND_LIMITED)) {
		u_int cw = CCV(ccv, snd_cwnd);
		u_int incr = CCV(ccv, t_maxseg);

		/*
		 * Regular in-order ACK, open the congestion window.
		 * Method depends on which congestion control state we're
		 * in (slow start or cong avoid) and if ABC (RFC 3465) is
		 * enabled.
		 *
		 * slow start: cwnd <= ssthresh
		 * cong avoid: cwnd > ssthresh
		 *
		 * slow start and ABC (RFC 3465):
		 *   Grow cwnd exponentially by the amount of data
		 *   ACKed capping the max increment per ACK to
		 *   (abc_l_var * maxseg) bytes.
		 *
		 * slow start without ABC (RFC 5681):
		 *   Grow cwnd exponentially by maxseg per ACK.
		 *
		 * cong avoid and ABC (RFC 3465):
		 *   Grow cwnd linearly by maxseg per RTT for each
		 *   cwnd worth of ACKed data.
		 *
		 * cong avoid without ABC (RFC 5681):
		 *   Grow cwnd linearly by approximately maxseg per RTT using
		 *   maxseg^2 / cwnd per ACK as the increment.
		 *   If cwnd > maxseg^2, fix the cwnd increment at 1 byte to
		 *   avoid capping cwnd.
		 */
		if (cw > CCV(ccv, snd_ssthresh)) {
			if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
				/*
				 * We have slipped into CA with
				 * CSS active. Deactivate all.
				 */
				/* Turn off the CSS flag */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
				/* Disable use of CSS in the future except long idle  */
				nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
				newreno_log_hystart_event(ccv, nreno, 11, CCV(ccv, snd_ssthresh));
			}
			if (V_tcp_do_rfc3465) {
				if (ccv->flags & CCF_ABC_SENTAWND)
					ccv->flags &= ~CCF_ABC_SENTAWND;
				else
					incr = 0;
			} else
				incr = max((incr * incr / cw), 1);
		} else if (V_tcp_do_rfc3465) {
			/*
			 * In slow-start with ABC enabled and no RTO in sight?
			 * (Must not use abc_l_var > 1 if slow starting after
			 * an RTO. On RTO, snd_nxt = snd_una, so the
			 * snd_nxt == snd_max check is sufficient to
			 * handle this).
			 *
			 * XXXLAS: Find a way to signal SS after RTO that
			 * doesn't rely on tcpcb vars.
			 */
			uint16_t abc_val;

			if (ccv->flags & CCF_USE_LOCAL_ABC)
				abc_val = ccv->labc;
			else
				abc_val = V_tcp_abc_l_var;

			/* SEARCH_begin */
			if (V_use_hystartpp) {
				#if defined(HYSTARTPP_LOG_ENABLED)
				log(LOG_INFO, "<%p> HyStartPP:[CCRG] [now %lu] Update HyStartPP in slow start\n", ccv, now_us); 
				#endif

				if ((ccv->flags & CCF_HYSTART_ALLOWED) &&
					(nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) &&
					((nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) == 0)) {

					#if defined(HYSTARTPP_LOG_ENABLED)
					log(LOG_INFO, "<%p> HyStartPP:[CCRG] [now %lu] HyStartPP is in slow start\n", ccv, now_us); 
					#endif
					/*
					 * Hystart is allowed and still enabled and we are not yet
					 * in CSS. Lets check to see if we can make a decision on
					 * if we need to go into CSS.
					 */
					if ((nreno->css_rttsample_count >= hystart_n_rttsamples) &&
						(nreno->css_current_round_minrtt != 0xffffffff) &&
						(nreno->css_lastround_minrtt != 0xffffffff)) {
						uint32_t rtt_thresh;

						/* Clamp (minrtt_thresh, lastround/8, maxrtt_thresh) */
						rtt_thresh = (nreno->css_lastround_minrtt >> 3);
						if (rtt_thresh < hystart_minrtt_thresh)
							rtt_thresh = hystart_minrtt_thresh;
						if (rtt_thresh > hystart_maxrtt_thresh)
							rtt_thresh = hystart_maxrtt_thresh;
						newreno_log_hystart_event(ccv, nreno, 1, rtt_thresh);
						if (nreno->css_current_round_minrtt >= (nreno->css_lastround_minrtt + rtt_thresh)) {

						#if defined(HYSTARTPP_LOG_ENABLED)
						log(LOG_INFO, "<%p> HyStartPP:[CCRG] [now %lu] HyStartPP is in CSS\n", ccv, now_us); 
						#endif
							/* Enter CSS */
							nreno->newreno_flags |= CC_NEWRENO_HYSTART_IN_CSS;
							nreno->css_fas_at_css_entry = nreno->css_lowrtt_fas;
							/*
							 * The draft (v4) calls for us to set baseline to css_current_round_min
							 * but that can cause an oscillation. We probably shoudl be using
							 * css_lastround_minrtt, but the authors insist that will cause
							 * issues on exiting early. We will leave the draft version for now
							 * but I suspect this is incorrect.
							 */
							nreno->css_baseline_minrtt = nreno->css_current_round_minrtt;
							nreno->css_entered_at_round = nreno->css_current_round;
							newreno_log_hystart_event(ccv, nreno, 2, rtt_thresh);
						}
					}
				}
			}
			/* SEARCH_end */

			if (CCV(ccv, snd_nxt) == CCV(ccv, snd_max))
				incr = min(ccv->bytes_this_ack,
				    ccv->nsegs * abc_val *
				    CCV(ccv, t_maxseg));
			else
				incr = min(ccv->bytes_this_ack, CCV(ccv, t_maxseg));

			/* Only if Hystart is enabled will the flag get set */
			if (nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) {
				/* SEARCH_begin */
				if (V_use_hystartpp)
					incr /= hystart_css_growth_div;
				/* SEARCH_end */
				newreno_log_hystart_event(ccv, nreno, 3, incr);
			}

		 	/* SEARCH_begin */
		 	/* 
			 * Invoke SEARCH slow start exit detector:
			 * - Monitors throughput evolution over time windows.
			 * - Returns true when delivery growth stalls, triggering slow start exit.
			 */
		 	if (V_use_search){
				/* implement search algorithm */
				if (search_update(ccv, now_us, rtt_us)) { /* returns true if exit  */
    				incr = 0;	/* freeze cwnd increase upon exit detection */
				}
		 	}
		 	/* SEARCH_end */
		}
		/* ABC is on by default, so incr equals 0 frequently. */
		if (incr > 0)
			CCV(ccv, snd_cwnd) = min(cw + incr,
			    TCP_MAXWIN << CCV(ccv, snd_scale));
	}
}

static void
newreno_after_idle(struct cc_var *ccv)
{
	struct newreno *nreno;

	nreno = ccv->cc_data;
	newreno_cc_after_idle(ccv);
	if ((nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) == 0) {
		/*
		 * Re-enable hystart if we have been idle.
		 */
		nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
		nreno->newreno_flags |= CC_NEWRENO_HYSTART_ENABLED;
		newreno_log_hystart_event(ccv, nreno, 12, CCV(ccv, snd_ssthresh));
	}
	/* SEARCH_begin */
	#if defined(DEBUG_LOG_ENABLED)
	log(LOG_INFO, "<%p> DEBUG:[CCRG] After idle [now %lu]\n", ccv, get_now_us()); 
	#endif
	search_reset(nreno, RESET_BIN_DURATION_TRUE);
	/* SEARCH_end */
}

/*
 * Perform any necessary tasks before we enter congestion recovery.
 */
static void
newreno_cong_signal(struct cc_var *ccv, uint32_t type)
{
	struct newreno *nreno;
	uint32_t beta, beta_ecn, cwin, factor;
	u_int mss;

	cwin = CCV(ccv, snd_cwnd);
	mss = tcp_fixed_maxseg(ccv->ccvc.tcp);
	nreno = ccv->cc_data;
	beta = (nreno == NULL) ? V_newreno_beta : nreno->beta;
	beta_ecn = (nreno == NULL) ? V_newreno_beta_ecn : nreno->beta_ecn;
	/*
	 * Note that we only change the backoff for ECN if the
	 * global sysctl V_cc_do_abe is set <or> the stack itself
	 * has set a flag in our newreno_flags (due to pacing) telling
	 * us to use the lower valued back-off.
	 */
	if ((type == CC_ECN) &&
	    (V_cc_do_abe ||
	    ((nreno != NULL) && (nreno->newreno_flags & CC_NEWRENO_BETA_ECN_ENABLED))))
		factor = beta_ecn;
	else
		factor = beta;

	/* Catch algos which mistakenly leak private signal types. */
	KASSERT((type & CC_SIGPRIVMASK) == 0,
	    ("%s: congestion signal type 0x%08x is private\n", __func__, type));

	cwin = max(((uint64_t)cwin * (uint64_t)factor) / (100ULL * (uint64_t)mss),
	    2) * mss;

	switch (type) {
	case CC_NDUPACK:
		/* SEARCH_begin */
		if (V_use_search){
			#if defined(ACK_LOG_ENABLED)
			log(LOG_INFO, "<%p> ACK:[CCRG] Loss happens at [now %lu]\n", ccv, get_now_us()); 
			#endif
		 	search_reset(nreno, RESET_BIN_DURATION_TRUE);
		}
		/* SEARCH_end */

		if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) {
			/* Make sure the flags are all off we had a loss */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			newreno_log_hystart_event(ccv, nreno, 10, CCV(ccv, snd_ssthresh));
		}
		if (!IN_FASTRECOVERY(CCV(ccv, t_flags))) {
			if (IN_CONGRECOVERY(CCV(ccv, t_flags) &&
			    V_cc_do_abe && V_cc_abe_frlossreduce)) {
				CCV(ccv, snd_ssthresh) =
				    ((uint64_t)CCV(ccv, snd_ssthresh) *
				     (uint64_t)beta) / (uint64_t)beta_ecn;
			}
			if (!IN_CONGRECOVERY(CCV(ccv, t_flags)))
				CCV(ccv, snd_ssthresh) = cwin;
			ENTER_RECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_ECN:
		/* SEARCH_begin */
		if (V_use_search){
			#if defined(ACK_LOG_ENABLED)
			log(LOG_INFO, "<%p> ACK:[CCRG] ECN flag happens at [now %lu]\n", ccv, get_now_us());
			#endif
		 	search_reset(nreno, RESET_BIN_DURATION_TRUE);
		}
		/* SEARCH_end */

		if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED) {
			/* Make sure the flags are all off we had a loss */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			newreno_log_hystart_event(ccv, nreno, 9, CCV(ccv, snd_ssthresh));
		}
		if (!IN_CONGRECOVERY(CCV(ccv, t_flags))) {
			CCV(ccv, snd_ssthresh) = cwin;
			CCV(ccv, snd_cwnd) = cwin;
			ENTER_CONGRECOVERY(CCV(ccv, t_flags));
		}
		break;
	case CC_RTO:
		/* SEARCH_begin */
		if (V_use_search){
			#if defined(ACK_LOG_ENABLED)
			log(LOG_INFO, "<%p> ACK:[CCRG] RTO happens at [now %lu]\n", ccv, get_now_us());
			#endif
		 	search_reset(nreno, RESET_BIN_DURATION_TRUE);
		}
		/* SEARCH_end */
		CCV(ccv, snd_ssthresh) = max(min(CCV(ccv, snd_wnd),
						 CCV(ccv, snd_cwnd)) / 2 / mss,
					     2) * mss;
		CCV(ccv, snd_cwnd) = mss;
		break;
	}
}

static int
newreno_ctl_output(struct cc_var *ccv, struct sockopt *sopt, void *buf)
{
	struct newreno *nreno;
	struct cc_newreno_opts *opt;

	if (sopt->sopt_valsize != sizeof(struct cc_newreno_opts))
		return (EMSGSIZE);

	if (CC_ALGO(ccv->ccvc.tcp) != &newreno_search_cc_algo)
		return (ENOPROTOOPT);

	nreno = (struct newreno *)ccv->cc_data;
	opt = buf;
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (opt->name) {
		case CC_NEWRENO_BETA:
			nreno->beta = opt->val;
			break;
		case CC_NEWRENO_BETA_ECN:
			nreno->beta_ecn = opt->val;
			nreno->newreno_flags |= CC_NEWRENO_BETA_ECN_ENABLED;
			break;
		default:
			return (ENOPROTOOPT);
		}
		break;
	case SOPT_GET:
		switch (opt->name) {
		case CC_NEWRENO_BETA:
			opt->val =  nreno->beta;
			break;
		case CC_NEWRENO_BETA_ECN:
			opt->val = nreno->beta_ecn;
			break;
		default:
			return (ENOPROTOOPT);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

static int
newreno_beta_handler(SYSCTL_HANDLER_ARGS)
{
	int error;
	uint32_t new;

	new = *(uint32_t *)arg1;
	error = sysctl_handle_int(oidp, &new, 0, req);
	if (error == 0 && req->newptr != NULL ) {
		if (arg1 == &VNET_NAME(newreno_beta_ecn) && !V_cc_do_abe)
			error = EACCES;
		else if (new == 0 || new > 100)
			error = EINVAL;
		else
			*(uint32_t *)arg1 = new;
	}

	return (error);
}

static void
newreno_newround(struct cc_var *ccv, uint32_t round_cnt)
{
	struct newreno *nreno;

	nreno = (struct newreno *)ccv->cc_data;
	/* We have entered a new round */
	nreno->css_lastround_minrtt = nreno->css_current_round_minrtt;
	nreno->css_current_round_minrtt = 0xffffffff;
	nreno->css_rttsample_count = 0;
	nreno->css_current_round = round_cnt;
	if ((nreno->newreno_flags & CC_NEWRENO_HYSTART_IN_CSS) &&
	    ((round_cnt - nreno->css_entered_at_round) >= hystart_css_rounds)) {
		/* Enter CA */
		if (ccv->flags & CCF_HYSTART_CAN_SH_CWND) {
			/*
			 * We engage more than snd_ssthresh, engage
			 * the brakes!! Though we will stay in SS to
			 * creep back up again, so lets leave CSS active
			 * and give us hystart_css_rounds more rounds.
			 */
			if (ccv->flags & CCF_HYSTART_CONS_SSTH) {
				/* SEARCH_begin */ //Comment out all cwnd and ssthresh setting or add flag if we use hystartpp
			 	if (V_use_hystartpp){
					CCV(ccv, snd_ssthresh) = ((nreno->css_lowrtt_fas + nreno->css_fas_at_css_entry) / 2);
					#if defined(HYSTARTPP_LOG_ENABLED)
					log(LOG_INFO, "<%p> HyStartPP:[CCRG] ssthresh is set by HyStartPP[1] [now %lu]\n", ccv, get_now_us());
					#endif
			 	}
			} else {
				if (V_use_hystartpp){
					CCV(ccv, snd_ssthresh) = nreno->css_lowrtt_fas;
					#if defined(HYSTARTPP_LOG_ENABLED)
					log(LOG_INFO, "<%p> HyStartPP:[CCRG] ssthresh is set by HyStartPP[2] [now %lu]\n", ccv, get_now_us()); 
					#endif
				}
			}
			if (V_use_hystartpp){
				CCV(ccv, snd_cwnd) = nreno->css_fas_at_css_entry;
				#if defined(HYSTARTPP_LOG_ENABLED)
				log(LOG_INFO, "<%p> HyStartPP:[CCRG] cwnd is set by HyStartPP [now %lu]\n", ccv, get_now_us());
				#endif
			}
			nreno->css_entered_at_round = round_cnt;
		} else {
			if (V_use_hystartpp){
				CCV(ccv, snd_ssthresh) = CCV(ccv, snd_cwnd);
				#if defined(HYSTARTPP_LOG_ENABLED)
				log(LOG_INFO, "<%p> HyStartPP:[CCRG] ssthresh is set by HyStartPP[3] [now %lu]\n", ccv, get_now_us());
				#endif
			}
			/* SEARCH_end */

			/* Turn off the CSS flag */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
			/* Disable use of CSS in the future except long idle  */
			nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_ENABLED;
		}
		newreno_log_hystart_event(ccv, nreno, 6, CCV(ccv, snd_ssthresh));
	}
	if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED)
		newreno_log_hystart_event(ccv, nreno, 4, round_cnt);
}

static void
newreno_rttsample(struct cc_var *ccv, uint32_t usec_rtt, uint32_t rxtcnt, uint32_t fas)
{
	struct newreno *nreno;

	nreno = (struct newreno *)ccv->cc_data;
	if (rxtcnt > 1) {
		/*
		 * Only look at RTT's that are non-ambiguous.
		 */
		return;
	}
	/* SEARCH_begin */
	nreno->last_rtt_sample = usec_rtt;	 
	/* SEARCH_end */
	nreno->css_rttsample_count++;
	nreno->css_last_fas = fas;
	if (nreno->css_current_round_minrtt > usec_rtt) {
		nreno->css_current_round_minrtt = usec_rtt;
		nreno->css_lowrtt_fas = nreno->css_last_fas;
	}
	if ((nreno->css_rttsample_count >= hystart_n_rttsamples) &&
	    (nreno->css_current_round_minrtt != 0xffffffff) &&
	    (nreno->css_current_round_minrtt < nreno->css_baseline_minrtt) &&
	    (nreno->css_lastround_minrtt != 0xffffffff)) {
		/*
		 * We were in CSS and the RTT is now less, we
		 * entered CSS erroneously.
		 */
		nreno->newreno_flags &= ~CC_NEWRENO_HYSTART_IN_CSS;
		newreno_log_hystart_event(ccv, nreno, 8, nreno->css_baseline_minrtt);
		nreno->css_baseline_minrtt = 0xffffffff;
	}
	if (nreno->newreno_flags & CC_NEWRENO_HYSTART_ENABLED)
		newreno_log_hystart_event(ccv, nreno, 5, usec_rtt);
}

SYSCTL_DECL(_net_inet_tcp_cc_newreno);
SYSCTL_NODE(_net_inet_tcp_cc, OID_AUTO, newreno,
    CTLFLAG_RW | CTLFLAG_MPSAFE, NULL,
    "New Reno related settings");

SYSCTL_PROC(_net_inet_tcp_cc_newreno, OID_AUTO, beta,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &VNET_NAME(newreno_beta), 3, &newreno_beta_handler, "IU",
    "New Reno beta, specified as number between 1 and 100");

SYSCTL_PROC(_net_inet_tcp_cc_newreno, OID_AUTO, beta_ecn,
    CTLFLAG_VNET | CTLTYPE_UINT | CTLFLAG_RW | CTLFLAG_NEEDGIANT,
    &VNET_NAME(newreno_beta_ecn), 3, &newreno_beta_handler, "IU",
    "New Reno beta ecn, specified as number between 1 and 100");


/* SEARCH_begin */
DECLARE_CC_MODULE(newreno, &newreno_search_cc_algo);
/* SEARCH_end */
MODULE_VERSION(newreno, 2);
