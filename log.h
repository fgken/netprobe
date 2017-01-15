#ifndef __LOG_H__
#define __LOG_H__

void
log_fatal(const char *format, ...);

void
log_err(const char *format, ...);

void
log_warn(const char *format, ...);

void
log_info(const char *format, ...);

void
log_debug(const char *format, ...);

#endif /* __LOG_H__ */
