typedef struct _hashtable {
	unsigned nTableSize;
	unsigned nTableMask;
	unsigned nNumOfElements;
	unsigned long nNextFreeElement;
	unsigned char nApplyCount;
} HashTable;

typedef union _zvalue_value {
	long lval;					/* long value */
	double dval;				/* double value */
	struct {
		char *val;
		int len;
	} str;
	HashTable *ht;				/* hash table value */
} zvalue_value;

struct _zval_struct {
	/* Variable information */
	zvalue_value value;		/* value */
	int type;
};

typedef struct _zval_struct zval;

#define Z_STRVAL(zval)	 	(zval).value.str.val
#define Z_STRVAL_P(zvalp) 	Z_STRVAL(*zvalp)
#define Z_STRVAL_PP(zvalpp) 	Z_STRVAL_P(*zvalpp)

#define Z_TYPE(zval)	 	(zval).type
#define Z_TYPE_P(zvalp) 	Z_TYPE(*zvalp)
#define Z_TYPE_PP(zvalpp) 	Z_TYPE_P(*zvalpp)
