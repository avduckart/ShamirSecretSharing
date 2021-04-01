#pragma once

#ifndef __CALC_H__
#define __CALC_H__

void calc_a0(share_data_t*);
void calc_a1(share_data_t*);
void calc_a2(share_data_t*);
void calc_term(restore_data_t*);
void run_calc(thread_t*, const share_data_t*);
void zero_part(part_t*);
void zero_parts(part_t*);
void close_threads(thread_t*);
result_t ready_to_write_parts(part_t*);
result_t handler(int);

#endif //__CALC_H__
