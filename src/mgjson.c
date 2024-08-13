// Copyright (c) 2004-2013 Sergey Lyubka
// Copyright (c) 2013-2024 Cesanta Software Limited
// All rights reserved
//
// This software is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see http://www.gnu.org/licenses/
//
// You are free to use this software under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this software under a commercial
// license, as set out in https://www.mongoose.ws/licensing/
//
// SPDX-License-Identifier: GPL-2.0-only or commercial

// NOTICE !!
// STRIPPED VERSION, FOR JSON FUNCTIONALITY WITHOUT THE OVERHEAD ... where applicable

#include "mgjson.h"
#include <assert.h>

#ifdef MG_ENABLE_LINES
#line 1 "src/base64.c"
#endif

static int mg_base64_encode_single(int c) {
  if (c < 26) {
    return c + 'A';
  } else if (c < 52) {
    return c - 26 + 'a';
  } else if (c < 62) {
    return c - 52 + '0';
  } else {
    return c == 62 ? '+' : '/';
  }
}

static int mg_base64_decode_single(int c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  } else if (c >= 'a' && c <= 'z') {
    return c + 26 - 'a';
  } else if (c >= '0' && c <= '9') {
    return c + 52 - '0';
  } else if (c == '+') {
    return 62;
  } else if (c == '/') {
    return 63;
  } else if (c == '=') {
    return 64;
  } else {
    return -1;
  }
}

size_t mg_base64_update(unsigned char ch, char *to, size_t n) {
  unsigned long rem = (n & 3) % 3;
  if (rem == 0) {
    to[n] = (char) mg_base64_encode_single(ch >> 2);
    to[++n] = (char) ((ch & 3) << 4);
  } else if (rem == 1) {
    to[n] = (char) mg_base64_encode_single(to[n] | (ch >> 4));
    to[++n] = (char) ((ch & 15) << 2);
  } else {
    to[n] = (char) mg_base64_encode_single(to[n] | (ch >> 6));
    to[++n] = (char) mg_base64_encode_single(ch & 63);
    n++;
  }
  return n;
}

size_t mg_base64_final(char *to, size_t n) {
  size_t saved = n;
  // printf("---[%.*s]\n", n, to);
  if (n & 3) n = mg_base64_update(0, to, n);
  if ((saved & 3) == 2) n--;
  // printf("    %d[%.*s]\n", n, n, to);
  while (n & 3) to[n++] = '=';
  to[n] = '\0';
  return n;
}

size_t mg_base64_encode(const unsigned char *p, size_t n, char *to, size_t dl) {
  size_t i, len = 0;
  if (dl > 0) to[0] = '\0';
  if (dl < ((n / 3) + (n % 3 ? 1 : 0)) * 4 + 1) return 0;
  for (i = 0; i < n; i++) len = mg_base64_update(p[i], to, len);
  len = mg_base64_final(to, len);
  return len;
}

size_t mg_base64_decode(const char *src, size_t n, char *dst, size_t dl) {
  const char *end = src == NULL ? NULL : src + n;  // Cannot add to NULL
  size_t len = 0;
  if (dl < n / 4 * 3 + 1) goto fail;
  while (src != NULL && src + 3 < end) {
    int a = mg_base64_decode_single(src[0]),
        b = mg_base64_decode_single(src[1]),
        c = mg_base64_decode_single(src[2]),
        d = mg_base64_decode_single(src[3]);
    if (a == 64 || a < 0 || b == 64 || b < 0 || c < 0 || d < 0) {
      goto fail;
    }
    dst[len++] = (char) ((a << 2) | (b >> 4));
    if (src[2] != '=') {
      dst[len++] = (char) ((b << 4) | (c >> 2));
      if (src[3] != '=') dst[len++] = (char) ((c << 6) | d);
    }
    src += 4;
  }
  dst[len] = '\0';
  return len;
fail:
  if (dl > 0) dst[0] = '\0';
  return 0;
}


#ifdef MG_ENABLE_LINES
#line 1 "src/fmt.c"
#endif

static bool is_digit(int c) {
  return c >= '0' && c <= '9';
}

static int addexp(char *buf, int e, int sign) {
  int n = 0;
  buf[n++] = 'e';
  buf[n++] = (char) sign;
  if (e > 400) return 0;
  if (e < 10) buf[n++] = '0';
  if (e >= 100) buf[n++] = (char) (e / 100 + '0'), e -= 100 * (e / 100);
  if (e >= 10) buf[n++] = (char) (e / 10 + '0'), e -= 10 * (e / 10);
  buf[n++] = (char) (e + '0');
  return n;
}

static int xisinf(double x) {
  union {
    double f;
    uint64_t u;
  } ieee754 = {x};
  return ((unsigned) (ieee754.u >> 32) & 0x7fffffff) == 0x7ff00000 &&
         ((unsigned) ieee754.u == 0);
}

static int xisnan(double x) {
  union {
    double f;
    uint64_t u;
  } ieee754 = {x};
  return ((unsigned) (ieee754.u >> 32) & 0x7fffffff) +
             ((unsigned) ieee754.u != 0) >
         0x7ff00000;
}

static size_t mg_dtoa(char *dst, size_t dstlen, double d, int width, bool tz) {
  char buf[40];
  int i, s = 0, n = 0, e = 0;
  double t, mul, saved;
  if (d == 0.0) return mg_snprintf(dst, dstlen, "%s", "0");
  if (xisinf(d)) return mg_snprintf(dst, dstlen, "%s", d > 0 ? "inf" : "-inf");
  if (xisnan(d)) return mg_snprintf(dst, dstlen, "%s", "nan");
  if (d < 0.0) d = -d, buf[s++] = '-';

  // Round
  saved = d;
  mul = 1.0;
  while (d >= 10.0 && d / mul >= 10.0) mul *= 10.0;
  while (d <= 1.0 && d / mul <= 1.0) mul /= 10.0;
  for (i = 0, t = mul * 5; i < width; i++) t /= 10.0;
  d += t;
  // Calculate exponent, and 'mul' for scientific representation
  mul = 1.0;
  while (d >= 10.0 && d / mul >= 10.0) mul *= 10.0, e++;
  while (d < 1.0 && d / mul < 1.0) mul /= 10.0, e--;
  // printf(" --> %g %d %g %g\n", saved, e, t, mul);

  if (e >= width && width > 1) {
    n = (int) mg_dtoa(buf, sizeof(buf), saved / mul, width, tz);
    // printf(" --> %.*g %d [%.*s]\n", 10, d / t, e, n, buf);
    n += addexp(buf + s + n, e, '+');
    return mg_snprintf(dst, dstlen, "%.*s", n, buf);
  } else if (e <= -width && width > 1) {
    n = (int) mg_dtoa(buf, sizeof(buf), saved / mul, width, tz);
    // printf(" --> %.*g %d [%.*s]\n", 10, d / mul, e, n, buf);
    n += addexp(buf + s + n, -e, '-');
    return mg_snprintf(dst, dstlen, "%.*s", n, buf);
  } else {
    for (i = 0, t = mul; t >= 1.0 && s + n < (int) sizeof(buf); i++) {
      int ch = (int) (d / t);
      if (n > 0 || ch > 0) buf[s + n++] = (char) (ch + '0');
      d -= ch * t;
      t /= 10.0;
    }
    // printf(" --> [%g] -> %g %g (%d) [%.*s]\n", saved, d, t, n, s + n, buf);
    if (n == 0) buf[s++] = '0';
    while (t >= 1.0 && n + s < (int) sizeof(buf)) buf[n++] = '0', t /= 10.0;
    if (s + n < (int) sizeof(buf)) buf[n + s++] = '.';
    // printf(" 1--> [%g] -> [%.*s]\n", saved, s + n, buf);
    for (i = 0, t = 0.1; s + n < (int) sizeof(buf) && n < width; i++) {
      int ch = (int) (d / t);
      buf[s + n++] = (char) (ch + '0');
      d -= ch * t;
      t /= 10.0;
    }
  }
  while (tz && n > 0 && buf[s + n - 1] == '0') n--;  // Trim trailing zeroes
  if (n > 0 && buf[s + n - 1] == '.') n--;           // Trim trailing dot
  n += s;
  if (n >= (int) sizeof(buf)) n = (int) sizeof(buf) - 1;
  buf[n] = '\0';
  return mg_snprintf(dst, dstlen, "%s", buf);
}

static size_t mg_lld(char *buf, int64_t val, bool is_signed, bool is_hex) {
  const char *letters = "0123456789abcdef";
  uint64_t v = (uint64_t) val;
  size_t s = 0, n, i;
  if (is_signed && val < 0) buf[s++] = '-', v = (uint64_t) (-val);
  // This loop prints a number in reverse order. I guess this is because we
  // write numbers from right to left: least significant digit comes last.
  // Maybe because we use Arabic numbers, and Arabs write RTL?
  if (is_hex) {
    for (n = 0; v; v >>= 4) buf[s + n++] = letters[v & 15];
  } else {
    for (n = 0; v; v /= 10) buf[s + n++] = letters[v % 10];
  }
  // Reverse a string
  for (i = 0; i < n / 2; i++) {
    char t = buf[s + i];
    buf[s + i] = buf[s + n - i - 1], buf[s + n - i - 1] = t;
  }
  if (val == 0) buf[n++] = '0';  // Handle special case
  return n + s;
}

static size_t scpy(void (*out)(char, void *), void *ptr, char *buf,
                          size_t len) {
  size_t i = 0;
  while (i < len && buf[i] != '\0') out(buf[i++], ptr);
  return i;
}

size_t mg_xprintf(void (*out)(char, void *), void *ptr, const char *fmt, ...) {
  size_t len = 0;
  va_list ap;
  va_start(ap, fmt);
  len = mg_vxprintf(out, ptr, fmt, &ap);
  va_end(ap);
  return len;
}

size_t mg_vxprintf(void (*out)(char, void *), void *param, const char *fmt,
                   va_list *ap) {
  size_t i = 0, n = 0;
  while (fmt[i] != '\0') {
    if (fmt[i] == '%') {
      size_t j, k, x = 0, is_long = 0, w = 0 /* width */, pr = ~0U /* prec */;
      char pad = ' ', minus = 0, c = fmt[++i];
      if (c == '#') x++, c = fmt[++i];
      if (c == '-') minus++, c = fmt[++i];
      if (c == '0') pad = '0', c = fmt[++i];
      while (is_digit(c)) w *= 10, w += (size_t) (c - '0'), c = fmt[++i];
      if (c == '.') {
        c = fmt[++i];
        if (c == '*') {
          pr = (size_t) va_arg(*ap, int);
          c = fmt[++i];
        } else {
          pr = 0;
          while (is_digit(c)) pr *= 10, pr += (size_t) (c - '0'), c = fmt[++i];
        }
      }
      while (c == 'h') c = fmt[++i];  // Treat h and hh as int
      if (c == 'l') {
        is_long++, c = fmt[++i];
        if (c == 'l') is_long++, c = fmt[++i];
      }
      if (c == 'p') x = 1, is_long = 1;
      if (c == 'd' || c == 'u' || c == 'x' || c == 'X' || c == 'p' ||
          c == 'g' || c == 'f') {
        bool s = (c == 'd'), h = (c == 'x' || c == 'X' || c == 'p');
        char tmp[40];
        size_t xl = x ? 2 : 0;
        if (c == 'g' || c == 'f') {
          double v = va_arg(*ap, double);
          if (pr == ~0U) pr = 6;
          k = mg_dtoa(tmp, sizeof(tmp), v, (int) pr, c == 'g');
        } else if (is_long == 2) {
          int64_t v = va_arg(*ap, int64_t);
          k = mg_lld(tmp, v, s, h);
        } else if (is_long == 1) {
          long v = va_arg(*ap, long);
          k = mg_lld(tmp, s ? (int64_t) v : (int64_t) (unsigned long) v, s, h);
        } else {
          int v = va_arg(*ap, int);
          k = mg_lld(tmp, s ? (int64_t) v : (int64_t) (unsigned) v, s, h);
        }
        for (j = 0; j < xl && w > 0; j++) w--;
        for (j = 0; pad == ' ' && !minus && k < w && j + k < w; j++)
          n += scpy(out, param, &pad, 1);
        n += scpy(out, param, (char *) "0x", xl);
        for (j = 0; pad == '0' && k < w && j + k < w; j++)
          n += scpy(out, param, &pad, 1);
        n += scpy(out, param, tmp, k);
        for (j = 0; pad == ' ' && minus && k < w && j + k < w; j++)
          n += scpy(out, param, &pad, 1);
      } else if (c == 'm' || c == 'M') {
        mg_pm_t f = va_arg(*ap, mg_pm_t);
        if (c == 'm') out('"', param);
        n += f(out, param, ap);
        if (c == 'm') n += 2, out('"', param);
      } else if (c == 'c') {
        int ch = va_arg(*ap, int);
        out((char) ch, param);
        n++;
      } else if (c == 's') {
        char *p = va_arg(*ap, char *);
        if (pr == ~0U) pr = p == NULL ? 0 : strlen(p);
        for (j = 0; !minus && pr < w && j + pr < w; j++)
          n += scpy(out, param, &pad, 1);
        n += scpy(out, param, p, pr);
        for (j = 0; minus && pr < w && j + pr < w; j++)
          n += scpy(out, param, &pad, 1);
      } else if (c == '%') {
        out('%', param);
        n++;
      } else {
        out('%', param);
        out(c, param);
        n += 2;
      }
      i++;
    } else {
      out(fmt[i], param), n++, i++;
    }
  }
  return n;
}


#ifdef MG_ENABLE_LINES
#line 1 "src/iobuf.c"
#endif

static size_t roundup(size_t size, size_t align) {
  return align == 0 ? size : (size + align - 1) / align * align;
}

int mg_iobuf_resize(struct mg_iobuf *io, size_t new_size) {
  int ok = 1;
  new_size = roundup(new_size, io->align);
  if (new_size == 0) {
    mg_bzero(io->buf, io->size);
    free(io->buf);
    io->buf = NULL;
    io->len = io->size = 0;
  } else if (new_size != io->size) {
    // NOTE(lsm): do not use realloc here. Use calloc/free only, to ease the
    // porting to some obscure platforms like FreeRTOS
    void *p = calloc(1, new_size);
    if (p != NULL) {
      size_t len = new_size < io->len ? new_size : io->len;
      if (len > 0 && io->buf != NULL) memmove(p, io->buf, len);
      mg_bzero(io->buf, io->size);
      free(io->buf);
      io->buf = (unsigned char *) p;
      io->size = new_size;
    } else {
      ok = 0;
      //MG_ERROR(("%lld->%lld", (uint64_t) io->size, (uint64_t) new_size));
    }
  }
  return ok;
}

int mg_iobuf_init(struct mg_iobuf *io, size_t size, size_t align) {
  io->buf = NULL;
  io->align = align;
  io->size = io->len = 0;
  return mg_iobuf_resize(io, size);
}

size_t mg_iobuf_add(struct mg_iobuf *io, size_t ofs, const void *buf,
                    size_t len) {
  size_t new_size = roundup(io->len + len, io->align);
  mg_iobuf_resize(io, new_size);      // Attempt to resize
  if (new_size != io->size) len = 0;  // Resize failure, append nothing
  if (ofs < io->len) memmove(io->buf + ofs + len, io->buf + ofs, io->len - ofs);
  if (buf != NULL) memmove(io->buf + ofs, buf, len);
  if (ofs > io->len) io->len += ofs - io->len;
  io->len += len;
  return len;
}

size_t mg_iobuf_del(struct mg_iobuf *io, size_t ofs, size_t len) {
  if (ofs > io->len) ofs = io->len;
  if (ofs + len > io->len) len = io->len - ofs;
  if (io->buf) memmove(io->buf + ofs, io->buf + ofs + len, io->len - ofs - len);
  if (io->buf) mg_bzero(io->buf + io->len - len, len);
  io->len -= len;
  return len;
}

void mg_iobuf_free(struct mg_iobuf *io) {
  mg_iobuf_resize(io, 0);
}


#ifdef MG_ENABLE_LINES
#line 1 "src/json.c"
#endif

static const char *escapeseq(int esc) {
  return esc ? "\b\f\n\r\t\\\"" : "bfnrt\\\"";
}

static char json_esc(int c, int esc) {
  const char *p, *esc1 = escapeseq(esc), *esc2 = escapeseq(!esc);
  for (p = esc1; *p != '\0'; p++) {
    if (*p == c) return esc2[p - esc1];
  }
  return 0;
}

static int mg_pass_string(const char *s, int len) {
  int i;
  for (i = 0; i < len; i++) {
    if (s[i] == '\\' && i + 1 < len && json_esc(s[i + 1], 1)) {
      i++;
    } else if (s[i] == '\0') {
      return MG_JSON_INVALID;
    } else if (s[i] == '"') {
      return i;
    }
  }
  return MG_JSON_INVALID;
}

static double mg_atod(const char *p, int len, int *numlen) {
  double d = 0.0;
  int i = 0, sign = 1;

  // Sign
  if (i < len && *p == '-') {
    sign = -1, i++;
  } else if (i < len && *p == '+') {
    i++;
  }

  // Decimal
  for (; i < len && p[i] >= '0' && p[i] <= '9'; i++) {
    d *= 10.0;
    d += p[i] - '0';
  }
  d *= sign;

  // Fractional
  if (i < len && p[i] == '.') {
    double frac = 0.0, base = 0.1;
    i++;
    for (; i < len && p[i] >= '0' && p[i] <= '9'; i++) {
      frac += base * (p[i] - '0');
      base /= 10.0;
    }
    d += frac * sign;
  }

  // Exponential
  if (i < len && (p[i] == 'e' || p[i] == 'E')) {
    int j, exp = 0, minus = 0;
    i++;
    if (i < len && p[i] == '-') minus = 1, i++;
    if (i < len && p[i] == '+') i++;
    while (i < len && p[i] >= '0' && p[i] <= '9' && exp < 308)
      exp = exp * 10 + (p[i++] - '0');
    if (minus) exp = -exp;
    for (j = 0; j < exp; j++) d *= 10.0;
    for (j = 0; j < -exp; j++) d /= 10.0;
  }

  if (numlen != NULL) *numlen = i;
  return d;
}

// Iterate over object or array elements
size_t mg_json_next(struct mg_str obj, size_t ofs, struct mg_str *key,
                    struct mg_str *val) {
  if (ofs >= obj.len) {
    ofs = 0;  // Out of boundaries, stop scanning
  } else if (obj.len < 2 || (*obj.buf != '{' && *obj.buf != '[')) {
    ofs = 0;  // Not an array or object, stop
  } else {
    struct mg_str sub = mg_str_n(obj.buf + ofs, obj.len - ofs);
    if (ofs == 0) ofs++, sub.buf++, sub.len--;
    if (*obj.buf == '[') {  // Iterate over an array
      int n = 0, o = mg_json_get(sub, "$", &n);
      if (n < 0 || o < 0 || (size_t) (o + n) > sub.len) {
        ofs = 0;  // Error parsing key, stop scanning
      } else {
        if (key) *key = mg_str_n(NULL, 0);
        if (val) *val = mg_str_n(sub.buf + o, (size_t) n);
        ofs = (size_t) (&sub.buf[o + n] - obj.buf);
      }
    } else {  // Iterate over an object
      int n = 0, o = mg_json_get(sub, "$", &n);
      if (n < 0 || o < 0 || (size_t) (o + n) > sub.len) {
        ofs = 0;  // Error parsing key, stop scanning
      } else {
        if (key) *key = mg_str_n(sub.buf + o, (size_t) n);
        sub.buf += o + n, sub.len -= (size_t) (o + n);
        while (sub.len > 0 && *sub.buf != ':') sub.len--, sub.buf++;
        if (sub.len > 0 && *sub.buf == ':') sub.len--, sub.buf++;
        n = 0, o = mg_json_get(sub, "$", &n);
        if (n < 0 || o < 0 || (size_t) (o + n) > sub.len) {
          ofs = 0;  // Error parsing value, stop scanning
        } else {
          if (val) *val = mg_str_n(sub.buf + o, (size_t) n);
          ofs = (size_t) (&sub.buf[o + n] - obj.buf);
        }
      }
    }
    // MG_INFO(("SUB ofs %u %.*s", ofs, sub.len, sub.buf));
    while (ofs && ofs < obj.len &&
           (obj.buf[ofs] == ' ' || obj.buf[ofs] == '\t' ||
            obj.buf[ofs] == '\n' || obj.buf[ofs] == '\r')) {
      ofs++;
    }
    if (ofs && ofs < obj.len && obj.buf[ofs] == ',') ofs++;
    if (ofs > obj.len) ofs = 0;
  }
  return ofs;
}

int mg_json_get(struct mg_str json, const char *path, int *toklen) {
  const char *s = json.buf;
  int len = (int) json.len;
  enum { S_VALUE, S_KEY, S_COLON, S_COMMA_OR_EOO } expecting = S_VALUE;
  unsigned char nesting[MG_JSON_MAX_DEPTH];
  int i = 0;             // Current offset in `s`
  int j = 0;             // Offset in `s` we're looking for (return value)
  int depth = 0;         // Current depth (nesting level)
  int ed = 0;            // Expected depth
  int pos = 1;           // Current position in `path`
  int ci = -1, ei = -1;  // Current and expected index in array

  if (toklen) *toklen = 0;
  if (path[0] != '$') return MG_JSON_INVALID;

#define MG_CHECKRET(x)                                  \
  do {                                                  \
    if (depth == ed && path[pos] == '\0' && ci == ei) { \
      if (toklen) *toklen = i - j + 1;                  \
      return j;                                         \
    }                                                   \
  } while (0)

// In the ascii table, the distance between `[` and `]` is 2.
// Ditto for `{` and `}`. Hence +2 in the code below.
#define MG_EOO(x)                                            \
  do {                                                       \
    if (depth == ed && ci != ei) return MG_JSON_NOT_FOUND;   \
    if (c != nesting[depth - 1] + 2) return MG_JSON_INVALID; \
    depth--;                                                 \
    MG_CHECKRET(x);                                          \
  } while (0)

  for (i = 0; i < len; i++) {
    unsigned char c = ((unsigned char *) s)[i];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;
    switch (expecting) {
      case S_VALUE:
        // p("V %s [%.*s] %d %d %d %d\n", path, pos, path, depth, ed, ci, ei);
        if (depth == ed) j = i;
        if (c == '{') {
          if (depth >= (int) sizeof(nesting)) return MG_JSON_TOO_DEEP;
          if (depth == ed && path[pos] == '.' && ci == ei) {
            // If we start the object, reset array indices
            ed++, pos++, ci = ei = -1;
          }
          nesting[depth++] = c;
          expecting = S_KEY;
          break;
        } else if (c == '[') {
          if (depth >= (int) sizeof(nesting)) return MG_JSON_TOO_DEEP;
          if (depth == ed && path[pos] == '[' && ei == ci) {
            ed++, pos++, ci = 0;
            for (ei = 0; path[pos] != ']' && path[pos] != '\0'; pos++) {
              ei *= 10;
              ei += path[pos] - '0';
            }
            if (path[pos] != 0) pos++;
          }
          nesting[depth++] = c;
          break;
        } else if (c == ']' && depth > 0) {  // Empty array
          MG_EOO(']');
        } else if (c == 't' && i + 3 < len && memcmp(&s[i], "true", 4) == 0) {
          i += 3;
        } else if (c == 'n' && i + 3 < len && memcmp(&s[i], "null", 4) == 0) {
          i += 3;
        } else if (c == 'f' && i + 4 < len && memcmp(&s[i], "false", 5) == 0) {
          i += 4;
        } else if (c == '-' || ((c >= '0' && c <= '9'))) {
          int numlen = 0;
          mg_atod(&s[i], len - i, &numlen);
          i += numlen - 1;
        } else if (c == '"') {
          int n = mg_pass_string(&s[i + 1], len - i - 1);
          if (n < 0) return n;
          i += n + 1;
        } else {
          return MG_JSON_INVALID;
        }
        MG_CHECKRET('V');
        if (depth == ed && ei >= 0) ci++;
        expecting = S_COMMA_OR_EOO;
        break;

      case S_KEY:
        if (c == '"') {
          int n = mg_pass_string(&s[i + 1], len - i - 1);
          if (n < 0) return n;
          if (i + 1 + n >= len) return MG_JSON_NOT_FOUND;
          if (depth < ed) return MG_JSON_NOT_FOUND;
          if (depth == ed && path[pos - 1] != '.') return MG_JSON_NOT_FOUND;
          // printf("K %s [%.*s] [%.*s] %d %d %d %d %d\n", path, pos, path, n,
          //        &s[i + 1], n, depth, ed, ci, ei);
          //  NOTE(cpq): in the check sequence below is important.
          //  strncmp() must go first: it fails fast if the remaining length
          //  of the path is smaller than `n`.
          if (depth == ed && path[pos - 1] == '.' &&
              strncmp(&s[i + 1], &path[pos], (size_t) n) == 0 &&
              (path[pos + n] == '\0' || path[pos + n] == '.' ||
               path[pos + n] == '[')) {
            pos += n;
          }
          i += n + 1;
          expecting = S_COLON;
        } else if (c == '}') {  // Empty object
          MG_EOO('}');
          expecting = S_COMMA_OR_EOO;
          if (depth == ed && ei >= 0) ci++;
        } else {
          return MG_JSON_INVALID;
        }
        break;

      case S_COLON:
        if (c == ':') {
          expecting = S_VALUE;
        } else {
          return MG_JSON_INVALID;
        }
        break;

      case S_COMMA_OR_EOO:
        if (depth <= 0) {
          return MG_JSON_INVALID;
        } else if (c == ',') {
          expecting = (nesting[depth - 1] == '{') ? S_KEY : S_VALUE;
        } else if (c == ']' || c == '}') {
          if (depth == ed && c == '}' && path[pos - 1] == '.')
            return MG_JSON_NOT_FOUND;
          if (depth == ed && c == ']' && path[pos - 1] == ',')
            return MG_JSON_NOT_FOUND;
          MG_EOO('O');
          if (depth == ed && ei >= 0) ci++;
        } else {
          return MG_JSON_INVALID;
        }
        break;
    }
  }
  return MG_JSON_NOT_FOUND;
}

struct mg_str mg_json_get_tok(struct mg_str json, const char *path) {
  int len = 0, ofs = mg_json_get(json, path, &len);
  return mg_str_n(ofs < 0 ? NULL : json.buf + ofs,
                  (size_t) (len < 0 ? 0 : len));
}

bool mg_json_get_num(struct mg_str json, const char *path, double *v) {
  int n, toklen, found = 0;
  if ((n = mg_json_get(json, path, &toklen)) >= 0 &&
      (json.buf[n] == '-' || (json.buf[n] >= '0' && json.buf[n] <= '9'))) {
    if (v != NULL) *v = mg_atod(json.buf + n, toklen, NULL);
    found = 1;
  }
  return found;
}

bool mg_json_get_bool(struct mg_str json, const char *path, bool *v) {
  int found = 0, off = mg_json_get(json, path, NULL);
  if (off >= 0 && (json.buf[off] == 't' || json.buf[off] == 'f')) {
    if (v != NULL) *v = json.buf[off] == 't';
    found = 1;
  }
  return found;
}

bool mg_json_unescape(struct mg_str s, char *to, size_t n) {
  size_t i, j;
  for (i = 0, j = 0; i < s.len && j < n; i++, j++) {
    if (s.buf[i] == '\\' && i + 5 < s.len && s.buf[i + 1] == 'u') {
      //  \uXXXX escape. We process simple one-byte chars \u00xx within ASCII
      //  range. More complex chars would require dragging in a UTF8 library,
      //  which is too much for us
      if (mg_str_to_num(mg_str_n(s.buf + i + 2, 4), 16, &to[j],
                        sizeof(uint8_t)) == false)
        return false;
      i += 5;
    } else if (s.buf[i] == '\\' && i + 1 < s.len) {
      char c = json_esc(s.buf[i + 1], 0);
      if (c == 0) return false;
      to[j] = c;
      i++;
    } else {
      to[j] = s.buf[i];
    }
  }
  if (j >= n) return false;
  if (n > 0) to[j] = '\0';
  return true;
}

char *mg_json_get_str(struct mg_str json, const char *path) {
  char *result = NULL;
  int len = 0, off = mg_json_get(json, path, &len);
  if (off >= 0 && len > 1 && json.buf[off] == '"') {
    if ((result = (char *) calloc(1, (size_t) len)) != NULL &&
        !mg_json_unescape(mg_str_n(json.buf + off + 1, (size_t) (len - 2)),
                          result, (size_t) len)) {
      free(result);
      result = NULL;
    }
  }
  return result;
}

char *mg_json_get_b64(struct mg_str json, const char *path, int *slen) {
  char *result = NULL;
  int len = 0, off = mg_json_get(json, path, &len);
  if (off >= 0 && json.buf[off] == '"' && len > 1 &&
      (result = (char *) calloc(1, (size_t) len)) != NULL) {
    size_t k = mg_base64_decode(json.buf + off + 1, (size_t) (len - 2), result,
                                (size_t) len);
    if (slen != NULL) *slen = (int) k;
  }
  return result;
}

char *mg_json_get_hex(struct mg_str json, const char *path, int *slen) {
  char *result = NULL;
  int len = 0, off = mg_json_get(json, path, &len);
  if (off >= 0 && json.buf[off] == '"' && len > 1 &&
      (result = (char *) calloc(1, (size_t) len / 2)) != NULL) {
    int i;
    for (i = 0; i < len - 2; i += 2) {
      mg_str_to_num(mg_str_n(json.buf + off + 1 + i, 2), 16, &result[i >> 1],
                    sizeof(uint8_t));
    }
    result[len / 2 - 1] = '\0';
    if (slen != NULL) *slen = len / 2 - 1;
  }
  return result;
}

long mg_json_get_long(struct mg_str json, const char *path, long dflt) {
  double dv;
  long result = dflt;
  if (mg_json_get_num(json, path, &dv)) result = (long) dv;
  return result;
}


#ifdef MG_ENABLE_LINES
#line 1 "src/str.c"
#endif

struct mg_str mg_str_s(const char *s) {
  struct mg_str str = {(char *) s, s == NULL ? 0 : strlen(s)};
  return str;
}

struct mg_str mg_str_n(const char *s, size_t n) {
  struct mg_str str = {(char *) s, n};
  return str;
}

static int mg_tolc(char c) {
  return (c >= 'A' && c <= 'Z') ? c + 'a' - 'A' : c;
}

int mg_casecmp(const char *s1, const char *s2) {
  int diff = 0;
  do {
    int c = mg_tolc(*s1++), d = mg_tolc(*s2++);
    diff = c - d;
  } while (diff == 0 && s1[-1] != '\0');
  return diff;
}

struct mg_str mg_strdup(const struct mg_str s) {
  struct mg_str r = {NULL, 0};
  if (s.len > 0 && s.buf != NULL) {
    char *sc = (char *) calloc(1, s.len + 1);
    if (sc != NULL) {
      memcpy(sc, s.buf, s.len);
      sc[s.len] = '\0';
      r.buf = sc;
      r.len = s.len;
    }
  }
  return r;
}

int mg_strcmp(const struct mg_str str1, const struct mg_str str2) {
  size_t i = 0;
  while (i < str1.len && i < str2.len) {
    int c1 = str1.buf[i];
    int c2 = str2.buf[i];
    if (c1 < c2) return -1;
    if (c1 > c2) return 1;
    i++;
  }
  if (i < str1.len) return 1;
  if (i < str2.len) return -1;
  return 0;
}

int mg_strcasecmp(const struct mg_str str1, const struct mg_str str2) {
  size_t i = 0;
  while (i < str1.len && i < str2.len) {
    int c1 = mg_tolc(str1.buf[i]);
    int c2 = mg_tolc(str2.buf[i]);
    if (c1 < c2) return -1;
    if (c1 > c2) return 1;
    i++;
  }
  if (i < str1.len) return 1;
  if (i < str2.len) return -1;
  return 0;
}

bool mg_match(struct mg_str s, struct mg_str p, struct mg_str *caps) {
  size_t i = 0, j = 0, ni = 0, nj = 0;
  if (caps) caps->buf = NULL, caps->len = 0;
  while (i < p.len || j < s.len) {
    if (i < p.len && j < s.len &&
        (p.buf[i] == '?' ||
         (p.buf[i] != '*' && p.buf[i] != '#' && s.buf[j] == p.buf[i]))) {
      if (caps == NULL) {
      } else if (p.buf[i] == '?') {
        caps->buf = &s.buf[j], caps->len = 1;     // Finalize `?` cap
        caps++, caps->buf = NULL, caps->len = 0;  // Init next cap
      } else if (caps->buf != NULL && caps->len == 0) {
        caps->len = (size_t) (&s.buf[j] - caps->buf);  // Finalize current cap
        caps++, caps->len = 0, caps->buf = NULL;       // Init next cap
      }
      i++, j++;
    } else if (i < p.len && (p.buf[i] == '*' || p.buf[i] == '#')) {
      if (caps && !caps->buf) caps->len = 0, caps->buf = &s.buf[j];  // Init cap
      ni = i++, nj = j + 1;
    } else if (nj > 0 && nj <= s.len && (p.buf[ni] == '#' || s.buf[j] != '/')) {
      i = ni, j = nj;
      if (caps && caps->buf == NULL && caps->len == 0) {
        caps--, caps->len = 0;  // Restart previous cap
      }
    } else {
      return false;
    }
  }
  if (caps && caps->buf && caps->len == 0) {
    caps->len = (size_t) (&s.buf[j] - caps->buf);
  }
  return true;
}

bool mg_span(struct mg_str s, struct mg_str *a, struct mg_str *b, char sep) {
  if (s.len == 0 || s.buf == NULL) {
    return false;  // Empty string, nothing to span - fail
  } else {
    size_t len = 0;
    while (len < s.len && s.buf[len] != sep) len++;  // Find separator
    if (a) *a = mg_str_n(s.buf, len);                // Init a
    if (b) *b = mg_str_n(s.buf + len, s.len - len);  // Init b
    if (b && len < s.len) b->buf++, b->len--;        // Skip separator
    return true;
  }
}

bool mg_str_to_num(struct mg_str str, int base, void *val, size_t val_len) {
  size_t i = 0, ndigits = 0;
  uint64_t max = val_len == sizeof(uint8_t)    ? 0xFF
                 : val_len == sizeof(uint16_t) ? 0xFFFF
                 : val_len == sizeof(uint32_t) ? 0xFFFFFFFF
                                               : (uint64_t) ~0;
  uint64_t result = 0;
  if (max == (uint64_t) ~0 && val_len != sizeof(uint64_t)) return false;
  if (base == 0 && str.len >= 2) {
    if (str.buf[i] == '0') {
      i++;
      base = str.buf[i] == 'b' ? 2 : str.buf[i] == 'x' ? 16 : 10;
      if (base != 10) ++i;
    } else {
      base = 10;
    }
  }
  switch (base) {
    case 2:
      while (i < str.len && (str.buf[i] == '0' || str.buf[i] == '1')) {
        uint64_t digit = (uint64_t) (str.buf[i] - '0');
        if (result > max / 2) return false;  // Overflow
        result *= 2;
        if (result > max - digit) return false;  // Overflow
        result += digit;
        i++, ndigits++;
      }
      break;
    case 10:
      while (i < str.len && str.buf[i] >= '0' && str.buf[i] <= '9') {
        uint64_t digit = (uint64_t) (str.buf[i] - '0');
        if (result > max / 10) return false;  // Overflow
        result *= 10;
        if (result > max - digit) return false;  // Overflow
        result += digit;
        i++, ndigits++;
      }
      break;
    case 16:
      while (i < str.len) {
        char c = str.buf[i];
        uint64_t digit = (c >= '0' && c <= '9')   ? (uint64_t) (c - '0')
                         : (c >= 'A' && c <= 'F') ? (uint64_t) (c - '7')
                         : (c >= 'a' && c <= 'f') ? (uint64_t) (c - 'W')
                                                  : (uint64_t) ~0;
        if (digit == (uint64_t) ~0) break;
        if (result > max / 16) return false;  // Overflow
        result *= 16;
        if (result > max - digit) return false;  // Overflow
        result += digit;
        i++, ndigits++;
      }
      break;
    default:
      return false;
  }
  if (ndigits == 0) return false;
  if (i != str.len) return false;
  if (val_len == 1) {
    *((uint8_t *) val) = (uint8_t) result;
  } else if (val_len == 2) {
    *((uint16_t *) val) = (uint16_t) result;
  } else if (val_len == 4) {
    *((uint32_t *) val) = (uint32_t) result;
  } else {
    *((uint64_t *) val) = (uint64_t) result;
  }
  return true;
}


#ifdef MG_ENABLE_LINES
#line 1 "src/util.c"
#endif

// Not using memset for zeroing memory, cause it can be dropped by compiler
// See https://github.com/cesanta/mongoose/pull/1265
void mg_bzero(volatile unsigned char *buf, size_t len) {
  if (buf != NULL) {
    while (len--) *buf++ = 0;
  }
}

#if MG_ENABLE_CUSTOM_RANDOM
#else
void mg_random(void *buf, size_t len) {
  bool done = false;
  unsigned char *p = (unsigned char *) buf;
#if MG_ARCH == MG_ARCH_UNIX
  FILE *fp = fopen("/dev/urandom", "rb");
  if (fp != NULL) {
    if (fread(buf, 1, len, fp) == len) done = true;
    fclose(fp);
  }
#endif
  // If everything above did not work, fallback to a pseudo random generator
  while (!done && len--) *p++ = (unsigned char) (rand() & 255);
}
#endif

char *mg_random_str(char *buf, size_t len) {
  size_t i;
  mg_random(buf, len);
  for (i = 0; i < len; i++) {
    uint8_t c = ((uint8_t *) buf)[i] % 62U;
    buf[i] = i == len - 1 ? (char) '\0'            // 0-terminate last byte
             : c < 26     ? (char) ('a' + c)       // lowercase
             : c < 52     ? (char) ('A' + c - 26)  // uppercase
                          : (char) ('0' + c - 52);     // numeric
  }
  return buf;
}

uint32_t mg_ntohl(uint32_t net) {
  uint8_t data[4] = {0, 0, 0, 0};
  memcpy(&data, &net, sizeof(data));
  return (((uint32_t) data[3]) << 0) | (((uint32_t) data[2]) << 8) |
         (((uint32_t) data[1]) << 16) | (((uint32_t) data[0]) << 24);
}

uint16_t mg_ntohs(uint16_t net) {
  uint8_t data[2] = {0, 0};
  memcpy(&data, &net, sizeof(data));
  return (uint16_t) ((uint16_t) data[1] | (((uint16_t) data[0]) << 8));
}

uint32_t mg_crc32(uint32_t crc, const char *buf, size_t len) {
  static const uint32_t crclut[16] = {
      // table for polynomial 0xEDB88320 (reflected)
      0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4,
      0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
      0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C};
  crc = ~crc;
  while (len--) {
    uint8_t b = *(uint8_t *) buf++;
    crc = crclut[(crc ^ b) & 0x0F] ^ (crc >> 4);
    crc = crclut[(crc ^ (b >> 4)) & 0x0F] ^ (crc >> 4);
  }
  return ~crc;
}


#if MG_ENABLE_CUSTOM_MILLIS
#else
uint64_t mg_millis(void) {
#if MG_ARCH == MG_ARCH_UNIX
  struct timespec ts = {0, 0};
  // See #1615 - prefer monotonic clock
  #define CLOCK_REALTIME			0
        #define CLOCK_MONOTONIC			1
#if defined(CLOCK_MONOTONIC_RAW)
  // Raw hardware-based time that is not subject to NTP adjustment
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#elif defined(CLOCK_MONOTONIC)
  // Affected by the incremental adjustments performed by adjtime and NTP
  clock_gettime(CLOCK_MONOTONIC, &ts);
#else
  // Affected by discontinuous jumps in the system time and by the incremental
  // adjustments performed by adjtime and NTP
  clock_gettime(CLOCK_REALTIME, &ts);
#endif
  return ((uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000);
#elif defined(ARDUINO)
  return (uint64_t) millis();
#else
  return (uint64_t) (time(NULL) * 1000);
#endif
}
#endif


#ifdef MG_ENABLE_LINES
#line 1 "src/printf.c"
#endif

size_t mg_queue_vprintf(struct mg_queue *q, const char *fmt, va_list *ap) {
  size_t len = mg_snprintf(NULL, 0, fmt, ap);
  char *buf;
  if (len == 0 || mg_queue_book(q, &buf, len + 1) < len + 1) {
    len = 0;  // Nah. Not enough space
  } else {
    len = mg_vsnprintf((char *) buf, len + 1, fmt, ap);
    mg_queue_add(q, len);
  }
  return len;
}

size_t mg_queue_printf(struct mg_queue *q, const char *fmt, ...) {
  va_list ap;
  size_t len;
  va_start(ap, fmt);
  len = mg_queue_vprintf(q, fmt, &ap);
  va_end(ap);
  return len;
}

static void mg_pfn_iobuf_private(char ch, void *param, bool expand) {
  struct mg_iobuf *io = (struct mg_iobuf *) param;
  if (expand && io->len + 2 > io->size) mg_iobuf_resize(io, io->len + 2);
  if (io->len + 2 <= io->size) {
    io->buf[io->len++] = (uint8_t) ch;
    io->buf[io->len] = 0;
  } else if (io->len < io->size) {
    io->buf[io->len++] = 0;  // Guarantee to 0-terminate
  }
}

static void mg_putchar_iobuf_static(char ch, void *param) {
  mg_pfn_iobuf_private(ch, param, false);
}

void mg_pfn_iobuf(char ch, void *param) {
  mg_pfn_iobuf_private(ch, param, true);
}

size_t mg_vsnprintf(char *buf, size_t len, const char *fmt, va_list *ap) {
  struct mg_iobuf io = {(uint8_t *) buf, len, 0, 0};
  size_t n = mg_vxprintf(mg_putchar_iobuf_static, &io, fmt, ap);
  if (n < len) buf[n] = '\0';
  return n;
}

size_t mg_snprintf(char *buf, size_t len, const char *fmt, ...) {
  va_list ap;
  size_t n;
  va_start(ap, fmt);
  n = mg_vsnprintf(buf, len, fmt, &ap);
  va_end(ap);
  return n;
}

char *mg_vmprintf(const char *fmt, va_list *ap) {
  struct mg_iobuf io = {0, 0, 0, 256};
  mg_vxprintf(mg_pfn_iobuf, &io, fmt, ap);
  return (char *) io.buf;
}

char *mg_mprintf(const char *fmt, ...) {
  char *s;
  va_list ap;
  va_start(ap, fmt);
  s = mg_vmprintf(fmt, &ap);
  va_end(ap);
  return s;
}

void mg_pfn_stdout(char c, void *param) {
  putchar(c);
  (void) param;
}

static char mg_esc(int c, bool esc) {
  const char *p, *esc1 = "\b\f\n\r\t\\\"", *esc2 = "bfnrt\\\"";
  for (p = esc ? esc1 : esc2; *p != '\0'; p++) {
    if (*p == c) return esc ? esc2[p - esc1] : esc1[p - esc2];
  }
  return 0;
}

static char mg_escape(int c) {
  return mg_esc(c, true);
}

static size_t qcpy(void (*out)(char, void *), void *ptr, char *buf,
                   size_t len) {
  size_t i = 0, extra = 0;
  for (i = 0; i < len && buf[i] != '\0'; i++) {
    char c = mg_escape(buf[i]);
    if (c) {
      out('\\', ptr), out(c, ptr), extra++;
    } else {
      out(buf[i], ptr);
    }
  }
  return i + extra;
}

static size_t bcpy(void (*out)(char, void *), void *arg, uint8_t *buf,
                   size_t len) {
  size_t i, j, n = 0;
  const char *t =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  for (i = 0; i < len; i += 3) {
    uint8_t c1 = buf[i], c2 = i + 1 < len ? buf[i + 1] : 0,
            c3 = i + 2 < len ? buf[i + 2] : 0;
    char tmp[4] = {t[c1 >> 2], t[(c1 & 3) << 4 | (c2 >> 4)], '=', '='};
    if (i + 1 < len) tmp[2] = t[(c2 & 15) << 2 | (c3 >> 6)];
    if (i + 2 < len) tmp[3] = t[c3 & 63];
    for (j = 0; j < sizeof(tmp) && tmp[j] != '\0'; j++) out(tmp[j], arg);
    n += j;
  }
  return n;
}

size_t mg_print_hex(void (*out)(char, void *), void *arg, va_list *ap) {
  size_t bl = (size_t) va_arg(*ap, int);
  uint8_t *p = va_arg(*ap, uint8_t *);
  const char *hex = "0123456789abcdef";
  size_t j;
  for (j = 0; j < bl; j++) {
    out(hex[(p[j] >> 4) & 0x0F], arg);
    out(hex[p[j] & 0x0F], arg);
  }
  return 2 * bl;
}
size_t mg_print_base64(void (*out)(char, void *), void *arg, va_list *ap) {
  size_t len = (size_t) va_arg(*ap, int);
  uint8_t *buf = va_arg(*ap, uint8_t *);
  return bcpy(out, arg, buf, len);
}

size_t mg_print_esc(void (*out)(char, void *), void *arg, va_list *ap) {
  size_t len = (size_t) va_arg(*ap, int);
  char *p = va_arg(*ap, char *);
  if (len == 0) len = p == NULL ? 0 : strlen(p);
  return qcpy(out, arg, p, len);
}


#ifdef MG_ENABLE_LINES
#line 1 "src/queue.c"
#endif

#if (defined(__GNUC__) && (__GNUC__ > 4) ||                                \
     (defined(__GNUC_MINOR__) && __GNUC__ == 4 && __GNUC_MINOR__ >= 1)) || \
    defined(__clang__)
#define MG_MEMORY_BARRIER() __sync_synchronize()
#elif defined(_MSC_VER) && _MSC_VER >= 1700
#define MG_MEMORY_BARRIER() MemoryBarrier()
#elif !defined(MG_MEMORY_BARRIER)
#define MG_MEMORY_BARRIER()
#endif

// Every message in a queue is prepended by a 32-bit message length (ML).
// If ML is 0, then it is the end, and reader must wrap to the beginning.
//
//  Queue when q->tail <= q->head:
//  |----- free -----| ML | message1 | ML | message2 |  ----- free ------|
//  ^                ^                               ^                   ^
// buf              tail                            head                len
//
//  Queue when q->tail > q->head:
//  | ML | message2 |----- free ------| ML | message1 | 0 |---- free ----|
//  ^               ^                 ^                                  ^
// buf             head              tail                               len

void mg_queue_init(struct mg_queue *q, char *buf, size_t size) {
  q->size = size;
  q->buf = buf;
  q->head = q->tail = 0;
}

static size_t mg_queue_read_len(struct mg_queue *q) {
  uint32_t n = 0;
  MG_MEMORY_BARRIER();
  memcpy(&n, q->buf + q->tail, sizeof(n));
  assert(q->tail + n + sizeof(n) <= q->size);
  return n;
}

static void mg_queue_write_len(struct mg_queue *q, size_t len) {
  uint32_t n = (uint32_t) len;
  memcpy(q->buf + q->head, &n, sizeof(n));
  MG_MEMORY_BARRIER();
}

size_t mg_queue_book(struct mg_queue *q, char **buf, size_t len) {
  size_t space = 0, hs = sizeof(uint32_t) * 2;  // *2 is for the 0 marker
  if (q->head >= q->tail && q->head + len + hs <= q->size) {
    space = q->size - q->head - hs;  // There is enough space
  } else if (q->head >= q->tail && q->tail > hs) {
    mg_queue_write_len(q, 0);  // Not enough space ahead
    q->head = 0;               // Wrap head to the beginning
  }
  if (q->head + hs + len < q->tail) space = q->tail - q->head - hs;
  if (buf != NULL) *buf = q->buf + q->head + sizeof(uint32_t);
  return space;
}

size_t mg_queue_next(struct mg_queue *q, char **buf) {
  size_t len = 0;
  if (q->tail != q->head) {
    len = mg_queue_read_len(q);
    if (len == 0) {  // Zero (head wrapped) ?
      q->tail = 0;   // Reset tail to the start
      if (q->head > q->tail) len = mg_queue_read_len(q);  // Read again
    }
  }
  if (buf != NULL) *buf = q->buf + q->tail + sizeof(uint32_t);
  assert(q->tail + len <= q->size);
  return len;
}

void mg_queue_add(struct mg_queue *q, size_t len) {
  assert(len > 0);
  mg_queue_write_len(q, len);
  assert(q->head + sizeof(uint32_t) * 2 + len <= q->size);
  q->head += len + sizeof(uint32_t);
}

void mg_queue_del(struct mg_queue *q, size_t len) {
  q->tail += len + sizeof(uint32_t);
  assert(q->tail + sizeof(uint32_t) <= q->size);
}
