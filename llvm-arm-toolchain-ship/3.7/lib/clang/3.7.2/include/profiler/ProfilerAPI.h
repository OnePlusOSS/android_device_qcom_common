/*===-- ProfilerAPI.h - Profiling support library support routines --------===*\
|*
|* (c) 2013 Qualcomm Innovation Center, Inc. All rights reserved.
|*
|*===----------------------------------------------------------------------===*|
|
|* This file declares API functions used by different profiling implementations.
|*
\*===----------------------------------------------------------------------===*/

#ifndef PROFILERAPI_H
#define PROFILERAPI_H

#ifdef __cplusplus
extern "C" {
#endif

/* start_profile - API for starting/resuming the profiler. This function
 * initializes all counters are back to 0.
 */
#ifdef ENABLE_PROFILING_APIS
int start_profile();
#else
inline int start_profile() {return 1;}
#endif

/* stop_profile - API for stopping/pausing the profiler. This function
 * dumps all counters to llvmprof.out.
 */
#ifdef ENABLE_PROFILING_APIS
int stop_profile();
#else
inline int stop_profile() {return 1;}
#endif

/* getErrorMsg - API for returning the error message if any error happened.
 */
#ifdef ENABLE_PROFILING_APIS
const char * get_profile_error_msg();
#else
inline const char * get_profile_error_msg() {return "";}
#endif

#ifdef __cplusplus
} // extern C
#endif

#endif