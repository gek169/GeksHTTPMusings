//Safe pointers for C!
//First Written by Gek (DMHSW) in February of 2021

//Q: What does "Safe" mean?
//A: No use after free, no read-past-by-one, and a built-in way of avoiding memory leaks using lifetimes, if you choose to use it.

//Q: How does it work?
//A: Every pointer is indexed by a unique hash- two size_ts. It can never appear again.
//On a 32 bit machine, two size_ts is equivalent to a single size_t on a 64 bit machine.
//(Either way, the end of the universe will happen before the hashes roll over...)
//Additionally, every pointer stores its size (in bytes) in .size. So you can't make the excuse that you "forgot to save the size"
//The pointers are stored in arrays.

//Q: Race conditions relating to memory access?
//A: If you use SAFEPTR_RESOURCE_LOCK() before you deref and SAFEPTR_RESOURCE_UNLOCK() when you're done with your pointer? no.

//Q: Is it thread safe
//A: Yes, implement SAFEPTR_RESOURCE_LOCK() and UNLOCK() to lock and unlock a mutex.

//Q: Is it fast?
//A: Not as fast as using raw pointers, but it's not a huge 

//Q: Use case?
//A: Anywhere where it's absolutely ESSENTIAL not to access malloc'd memory in an invalid way.

//Q: 

#ifndef C_SAFEMEM_H
#define C_SAFEMEM_H
#include <stdlib.h>
#include <string.h>
 //for memcpy
#include <stdint.h>
#include <stddef.h>
// for size_t

#ifndef SAFEPTR_RESOURCE_LOCK
#define SAFEPTR_RESOURCE_LOCK() /* a comment*/
#define SAFEPTR_RESOURCE_UNLOCK() /* a comment*/
#endif

typedef struct {
	size_t part2;	//Low
	size_t part1;	//High
} safeptrhash;
#define SAFEPTR_INIT	(safepointer){0,0,(safeptrhash){0,0}}
#define SAFEPTRHASH_MAX	(safeptrhash){SIZE_MAX,SIZE_MAX}
#define SAFEPTRHASH_ZERO (safeptrhash){0,0}
#define SAFEPTR_GUARD_IF(type, safeptr, i) if(((i)*sizeof(type)) < safeptr.size)
#define SAFEPTR_TRY_GET(target, type, safeptr, i) \
	{type* p = safepointer_deref(safeptr); if(p) SAFEPTR_GUARD_IF(type, safeptr, i) {target = p[i];}}
#define SAFEPTR_TRY_WRITE(type, safeptr, i, value) \
	{type* p = safepointer_deref(safeptr); if(p) SAFEPTR_GUARD_IF(type, safeptr, i) {p[i] = value;}}
typedef struct{	size_t indy; 	
				size_t size; 		//Size of the buffer being pointed to.
				safeptrhash hash;	//Unique identifier for this malloc.
			} safepointer;
typedef enum {
	C_SAFEMEM_NO_ERR = 0,
	C_SAFEMEM_BAD_PTR = 1,
	C_SAFEMEM_BAD_INDEX = 2,
	C_SAFEMEM_INVALID_STATE = 3,
	C_SAFEMEM_FAILED_MALLOC = 4
} c_safemem_error_state;

void*					safepointer_deref(safepointer f);
safepointer 			safepointer_malloc(size_t s, size_t lifetime);
#define SAFEPTR_MALLOC(type, n, life) safepointer_malloc(sizeof(type) * n, life)
c_safemem_error_state 	safepointer_free(safepointer f); //returns ERROR STATE
c_safemem_error_state	safepointer_collect_garbage();		//Iterate lifetimes and automatically free pointers with exhausted lifetimes.
c_safemem_error_state	safepointer_collect_all();			//Iterate lifetimes and automatically free pointers with exhausted lifetimes.
void					safepointer_keepalive(safepointer f, size_t lifetime);

extern void** c_safemem_ptrs;
extern size_t c_safemem_nptrs;
extern safeptrhash c_safemem_hash_counter;
extern size_t c_safemem_failed_malloc;
#ifdef C_SAFEMEM_IMPL
#define C_SAFEMEM_BLOCK_SIZE 512

//Vectors representing current state.

void** c_safemem_ptrs = NULL;
safeptrhash* c_safemem_hashes = NULL;
size_t* c_safemem_scheduled_deaths = NULL;
size_t c_safemem_nptrs = 0;
size_t c_safemem_failed_malloc = 0;
size_t quick = 0;
safeptrhash c_safemem_hash_counter = {0,1};
size_t c_safemem_update_calls = 1; //Counts.

static inline void safepointer_increment_hash_counter(){
	c_safemem_hash_counter.part1++;
	if(c_safemem_hash_counter.part1 == 0)c_safemem_hash_counter.part2++;
}

static inline void safepointer_increment_calls(){
	c_safemem_update_calls++;
}


//Expand storage


size_t safepointer_expand_storage(){
	SAFEPTR_RESOURCE_LOCK();
	if(c_safemem_failed_malloc) goto error;
	void** 			c_safemem_ptrs_old = 				c_safemem_ptrs;
	safeptrhash* 	c_safemem_hashes_old = 				c_safemem_hashes;
	size_t* 		c_safemem_scheduled_deaths_old = 	c_safemem_scheduled_deaths;
	size_t 			c_safemem_nptrs_old = 				c_safemem_nptrs;

	c_safemem_nptrs += C_SAFEMEM_BLOCK_SIZE; 
#ifdef C_SAFEMEM_DEBUG
	printf("Expanding storage... %zu bytes allocated for tables, total!\n", c_safemem_nptrs * sizeof(void*));
#endif	
	c_safemem_ptrs =			 			calloc(1,sizeof(void*) * c_safemem_nptrs);
	if(!c_safemem_ptrs) goto error;

	if(c_safemem_ptrs_old){ memcpy(	c_safemem_ptrs, 
									c_safemem_ptrs_old, 
									c_safemem_nptrs_old * sizeof(void*)
								); 
								free(c_safemem_ptrs_old);
						}
	c_safemem_hashes = 			calloc(1,sizeof(safeptrhash) * c_safemem_nptrs);
	if(!c_safemem_hashes) goto error;
	if(c_safemem_hashes_old) {
								memcpy(	c_safemem_hashes, 
										c_safemem_hashes_old, 
										c_safemem_nptrs_old * sizeof(safeptrhash)
									);
									free(c_safemem_hashes_old);
							}
	c_safemem_scheduled_deaths = 	calloc(1,sizeof(size_t) * c_safemem_nptrs);
	if(!c_safemem_scheduled_deaths) goto error;
	if(c_safemem_scheduled_deaths_old) {
				memcpy(	c_safemem_scheduled_deaths, 
										c_safemem_scheduled_deaths_old, 
										c_safemem_nptrs_old * sizeof(size_t)
									);free(c_safemem_scheduled_deaths_old);
	}
	SAFEPTR_RESOURCE_UNLOCK();
	return 0;

	error:
#ifdef C_SAFEMEM_DEBUG
	puts("FAILED MALLOC\n");
#endif
	c_safemem_failed_malloc = 1;
	SAFEPTR_RESOURCE_UNLOCK();
	return 1;
}


//MALOC IMPLEMENTATION
safepointer safepointer_malloc(size_t sz, size_t lifetime){
	safepointer s;
	s.indy = SIZE_MAX;
	s.hash = SAFEPTRHASH_MAX;
	s.size = 0;
	size_t end = c_safemem_nptrs;
	SAFEPTR_RESOURCE_LOCK();
	if(c_safemem_failed_malloc) {SAFEPTR_RESOURCE_UNLOCK();return s;}
	while(s.indy == SIZE_MAX){
		for(size_t i = quick; i < end;i++)
			if(c_safemem_ptrs[i] == NULL){
				safepointer_increment_hash_counter();
				s.hash = c_safemem_hash_counter;
#ifdef C_SAFEMEM_DEBUG
				printf("\nALLOCED, HASH = %zu, %zu", s.hash.part2, s.hash.part1);
#endif
				s.indy = i;
				quick = i + 1;
				break;
			}
		if(s.indy == SIZE_MAX && quick != 0){
			end=quick;
			quick = 0;
		} else if(s.indy == SIZE_MAX){
			SAFEPTR_RESOURCE_UNLOCK();
			if(safepointer_expand_storage()){
#ifdef C_SAFEMEM_DEBUG
			puts("FAILED MALLOC\n");
#endif
				return s;
			}
			
			SAFEPTR_RESOURCE_LOCK();
			quick = 0;
			end = c_safemem_nptrs;
		}
	}	//EOF WHILE
	if(s.indy != SIZE_MAX){

		c_safemem_ptrs[s.indy] = calloc(1,sz);
		if(c_safemem_ptrs[s.indy] == NULL){
#ifdef C_SAFEMEM_DEBUG
			puts("FAILED MALLOC\n");
#endif
			c_safemem_failed_malloc = 1;
			SAFEPTR_RESOURCE_UNLOCK();
			return s;
		}
		s.size = sz;
#ifdef C_SAFEMEM_DEBUG
		puts("Successful Malloc!\n");
#endif
		c_safemem_hashes[s.indy] = s.hash;
		c_safemem_scheduled_deaths[s.indy] = c_safemem_update_calls + lifetime;
	}
	SAFEPTR_RESOURCE_UNLOCK();
	return s;
}

//COLLECT GARBAGE
c_safemem_error_state safepointer_collect_garbage(){
	
	SAFEPTR_RESOURCE_LOCK();
	if(c_safemem_failed_malloc) goto error;
	for(size_t i = 0; i < c_safemem_nptrs;i++)
		if(c_safemem_ptrs[i])
		if(c_safemem_scheduled_deaths[i] == c_safemem_update_calls)
		{
#ifdef C_SAFEMEM_DEBUG
			puts("--               ---    Collecting a pointer...\n");
#endif
			free(c_safemem_ptrs[i]); 
			c_safemem_ptrs[i] = NULL;
			c_safemem_scheduled_deaths[i]=0;
			c_safemem_hashes[i].part1 = 0;
			c_safemem_hashes[i].part2 = 0;
		}
	safepointer_increment_calls();
	SAFEPTR_RESOURCE_UNLOCK();
	return C_SAFEMEM_NO_ERR;

	error:
	SAFEPTR_RESOURCE_UNLOCK();
	return C_SAFEMEM_FAILED_MALLOC;
}


c_safemem_error_state safepointer_collect_all(){
	
	SAFEPTR_RESOURCE_LOCK();
	if(c_safemem_failed_malloc) goto error;
	for(size_t i = 0; i < c_safemem_nptrs;i++)
		if(c_safemem_ptrs[i])
		{
#ifdef C_SAFEMEM_DEBUG
			puts("--               ---    Cleaning up a pointer...\n");
#endif
			free(c_safemem_ptrs[i]); 
			c_safemem_ptrs[i] = NULL;
			c_safemem_scheduled_deaths[i]=0;
			c_safemem_hashes[i].part1 = 0;
			c_safemem_hashes[i].part2 = 0;
		}

	if(c_safemem_ptrs)free(c_safemem_ptrs);	c_safemem_ptrs = NULL;
	if(c_safemem_scheduled_deaths)free(c_safemem_scheduled_deaths);	c_safemem_scheduled_deaths = NULL;
	if(c_safemem_hashes)free(c_safemem_hashes);	c_safemem_hashes = NULL;
	c_safemem_failed_malloc = 0;
	c_safemem_hash_counter = (safeptrhash){0,1};
	c_safemem_update_calls = 1; //Counts.
	
	SAFEPTR_RESOURCE_UNLOCK();
	return C_SAFEMEM_NO_ERR;

	error:
	SAFEPTR_RESOURCE_UNLOCK();
	return C_SAFEMEM_FAILED_MALLOC;
}


//POINTER DEREF IMPLEMENTATION

void* safepointer_deref(safepointer f){
	void* p = NULL;
	if(c_safemem_failed_malloc) 	return NULL;
	if(f.indy >= c_safemem_nptrs)	return NULL;
	if(c_safemem_hashes[f.indy].part1 == f.hash.part1 &&
		c_safemem_hashes[f.indy].part2 == f.hash.part2)
	{
		p = c_safemem_ptrs[f.indy];
	}
	return p;
}

void	safepointer_keepalive(safepointer f, size_t lifetime){
		SAFEPTR_RESOURCE_LOCK();
		if(c_safemem_failed_malloc) 	goto end;
		if(f.indy >= c_safemem_nptrs)	goto end;
		if(c_safemem_hashes[f.indy].part1 == f.hash.part1 &&
			c_safemem_hashes[f.indy].part2 == f.hash.part2)
		{
			c_safemem_scheduled_deaths[f.indy] = c_safemem_update_calls + lifetime;
		}
		end:
		SAFEPTR_RESOURCE_UNLOCK();
}


//FREE IMPLEMENTATION

c_safemem_error_state safepointer_free(const safepointer f){
	if(c_safemem_failed_malloc) return C_SAFEMEM_FAILED_MALLOC;
	if(f.indy >= c_safemem_nptrs) return C_SAFEMEM_BAD_PTR;
	if(	c_safemem_ptrs[f.indy] &&
		c_safemem_hashes[f.indy].part1 == f.hash.part1 &&
		c_safemem_hashes[f.indy].part2 == f.hash.part2 )
		{
#ifdef C_SAFEMEM_DEBUG
			printf("Freeing pointer... size was %zu\n",f.size);
			if(f.size == 5000)
				exit(1);
#endif
			SAFEPTR_RESOURCE_LOCK();
				free(c_safemem_ptrs[f.indy]); 
				c_safemem_ptrs[f.indy] = NULL;
				c_safemem_scheduled_deaths[f.indy]=0;
				c_safemem_hashes[f.indy].part1 = 0;
				c_safemem_hashes[f.indy].part2 = 0;
			SAFEPTR_RESOURCE_UNLOCK();
			return C_SAFEMEM_NO_ERR;
		}
	else
		{return C_SAFEMEM_INVALID_STATE;}
	
}
#endif
#endif
