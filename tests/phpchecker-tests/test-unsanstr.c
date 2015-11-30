#include "testmacro.h"

extern int zend_hash_find(HashTable *ht, const char *ch, unsigned i, void **data);

void sanitized() {
   zval **z;
   char *tmp;
   HashTable *ht;
   const char *ch = "c";
   unsigned i = 0;
   zend_hash_find(ht, ch, i, (void **) &z);
   if (Z_TYPE_PP(z) == 1) 
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

