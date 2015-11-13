#include "testmacro.h"

extern int zend_hash_find(HashTable *ht, const char *ch, unsigned i, void **data);
extern void convert_to_string(zval *op);

void sanitized() {
   zval **z;
   char *tmp;
   HashTable *ht;
   const char *ch = "c";
   unsigned i = 0;
   zend_hash_find(ht, ch, i, (void **) &z);
   convert_to_string(*z);
   tmp = Z_STRVAL_PP(z);
}

void unsanitized() {
   zval **z;
   char *tmp;
   HashTable *ht;
   const char *ch = "c";
   unsigned i = 0;
   zend_hash_find(ht, ch, i, (void **) &z);
   tmp = Z_STRVAL_PP(z);
}
