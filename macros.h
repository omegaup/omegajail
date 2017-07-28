#ifndef MACROS_H_
#define MACROS_H_

#define DISALLOW_COPY_AND_ASSIGN(Type) \
  Type(const Type&) = delete;          \
  Type operator=(const Type&) = delete

#endif  // MACROS_H_
