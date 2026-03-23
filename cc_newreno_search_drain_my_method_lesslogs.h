/*-
 * Copyright (c) 2017 Tom Jones <tj@enoti.me>
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _CC_NEWRENO_H
#define _CC_NEWRENO_H
 
#define CCALGONAME_NEWRENO "newreno_search"
 
typedef uint16_t search_bin_t;											/* Bin type for SEARCH; change width (e.g., uint32_t/uint64_t) to adjust bin size */
#define MAX_US_INT 0xffff	//16bit:0xffff   32bit:0xffffffff			/* Maximum size of each bin in bits */

#define SEARCH_WINDOW_SIZE_FACTOR 35 									/* Multiply with (initial RTT / 10) to set the window size */
#define SEARCH_WIN_BINS 10												/* Number of bins in a window */
#define SEARCH_EXTRA_ACKED_BINS 1  										/* Number of additional bins to calculate delivery window (as this is cumulative, we need one more bin) */
#define SEARCH_EXTRA_SENT_BINS 35										/* Number of additional bins to cover data after shiftting by RTT */
#define SEARCH_ACKED_BINS (SEARCH_WIN_BINS + SEARCH_EXTRA_ACKED_BINS)	/* Number of total bins in a acked window */
#define SEARCH_SENT_BINS (SEARCH_WIN_BINS + SEARCH_EXTRA_SENT_BINS)		/* Number of total bins in a acked window */
#define SEARCH_THRESH 26												/* Threshold for exiting from slow start in percentage */
#define SEARCH_ALPHA MAX_US_INT											/* Alpha factor for determining missed bin limit in SEARCH. Currently disabled */

/**
 * Control whether SEARCH bin duration is reset.
 * Used during SEARCH reset to either reinitialize or
 * preserve existing bin duration.
 */
enum unset_bin_duration {
	RESET_BIN_DURATION_TRUE,		// Reset bin duration
	RESET_BIN_DURATION_FALSE		// Do not reset bin duration
};
 
struct newreno {
	uint32_t beta;
	uint32_t beta_ecn;
	uint32_t newreno_flags;
	uint32_t css_baseline_minrtt;
	uint32_t css_current_round_minrtt;
	uint32_t css_lastround_minrtt;
	uint32_t css_rttsample_count;
	uint32_t css_entered_at_round;
	uint32_t css_current_round;
	uint32_t css_fas_at_css_entry;
	uint32_t css_lowrtt_fas;
	uint32_t css_last_fas;
 
	/* SEARCH_begin */
	uint32_t last_rtt_sample;							/* Most recent RTT sample (in microseconds) from rttsample() */
	uint32_t search_bin_duration_us;					/* duration of each bin in microsecond */
	int32_t  search_curr_idx;							/* total number of bins */
	uint64_t search_bin_end_us;							/* end time of the latest bin in microsecond */
	search_bin_t search_acked_bin[SEARCH_ACKED_BINS];	/* array to keep acked bytes for bins */
	search_bin_t search_sent_bin[SEARCH_SENT_BINS];		/* array to keep sent bytes for bins */
	uint8_t search_scale_factor;						/* scale factor to fit the value with bin size */
	uint64_t search_cumulative_acked_bytes;				/* cumulative byte acked */
	uint64_t search_targeted_cwnd;  					/* Rollback CWND target = BDP estimate from one RTT earlier; used to initiate SEARCH drain */
	uint8_t search_cwnd_reduction_to_target; 			/* Triggers CWND drain toward search_targeted_cwnd */
	uint32_t search_drain_ackedseg_thresh;        		/* ACKed-segment threshold to permit CWND increase during drain */
	uint32_t search_drain_ackedseg;      	 			/* Accumulates number of segments ACKed during SEARCH drain */

};

/* Access SEARCH ACKed-bin ring buffer (modulo indexed) */
#undef  SEARCH_ACKED_BIN
#define SEARCH_ACKED_BIN(ccv, i) (((struct newreno*)(ccv)->cc_data)->search_acked_bin[(i)% SEARCH_ACKED_BINS])

/* Access SEARCH sent-bin ring buffer (modulo indexed) */
#undef  SEARCH_SENT_BIN
#define SEARCH_SENT_BIN(ccv, i)  (((struct newreno*)(ccv)->cc_data)->search_sent_bin[(i) % SEARCH_SENT_BINS])

struct cc_newreno_opts {
	int			name;
	uint32_t	val;
};

#define CC_NEWRENO_BETA			1	/* Beta for normal DUP-ACK/Sack recovery */
#define CC_NEWRENO_BETA_ECN		2	/* ECN Beta for Abe */

/* Flags values */
#define CC_NEWRENO_HYSTART_ENABLED	0x0002	/* We can do hystart, a loss removes this flag */
#define CC_NEWRENO_HYSTART_IN_CSS	0x0004	/* If we enter hystart CSS this flag is set */
#define CC_NEWRENO_BETA_ECN_ENABLED	0x0020
#endif /* _CC_NEWRENO_H */
