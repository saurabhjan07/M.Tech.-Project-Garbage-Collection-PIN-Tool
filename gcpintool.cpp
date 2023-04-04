/* =======================================================================================================================================
==========================================================================================================================================

This Pintool performs Garbage Collection (GC) for C Programs. This Pintool performs GC in the following manner:

1. Find the RTN object corresponding to the app's free() using PIN's RTN_FindByName().
   Note that the image that contains this function is usually your app's runtime library (i.e. libc on Linux).

2. Get a pointer to the app's free() function using RTN_Funptr()

3. Call the function using its pointer using PIN_CallApplicationFunction() and provide the pointer that needs to be freed as an argument.

==========================================================================================================================================
========================================================================================================================================*/

#include "pin.H"
#include <iostream>
#include<stdio.h>
#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <map>

using namespace std;

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */

#if defined(TARGET_MAC)
#define MAIN "_main"
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MAIN "main"
#define MALLOC "malloc"
#define FREE "free"
#endif

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

std::multimap<char *, ADDRINT> gcmap;
std::multimap<char *, ADDRINT>::iterator gc_it;
char * funcname, *funcname1, *funcmain ;
string name, namemain = "main";
AFUNPTR freeptr=0;
bool disable = false;
ADDRINT lowadd, highadd, global=0;
ADDRINT value, addr1;
/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "-o", "gc9.out", "specify trace file name");

/* ===================================================================== */


/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */


/* ===================================================================== */
/* This Analysis Routine maintains the data structure which stores and   */
/* remove the memory addresses being allocated and deallocated		 */
/* ===================================================================== */

VOID globalRecord(char *grname, ADDRINT* addr) //To keep global garbage record and to change its scope
{
	
	addr1 = (ADDRINT)addr;
    	PIN_SafeCopy(&value, addr, sizeof(ADDRINT)); // In "value" we get the address pointed by global "*addr" using PIN_Safecopy
	//cout<<hex<<addr1<<"    "<<hex<<value<<endl;
	if(addr1<=highadd)
	{
		for(gc_it = gcmap.begin() ; gc_it != gcmap.end() ; ++gc_it)
			if(gc_it->second == value)
			{	
				if( strcmp(gc_it->first, funcmain) )
				{	
					gcmap.erase (gc_it);
					gcmap.insert(std::pair<char *,ADDRINT>(funcmain,value)); // changing scope to "main"
				}
			}
	}
}

VOID garbageRecord(char *grname, ADDRINT address, UINT32 i) // To keep all garbage record other than global
{
	static UINT32 a=0;
	UINT32 flag=0;
	funcmain = strdup(namemain.c_str());
	switch(i)
	{
		case 0: //EXECUTES WHEN MALLOC, CALLOC IS CALLED.

		if(a==0)
		{	a++;
			break;
		}
		if (address != 0)
				gcmap.insert(std::pair<char *, ADDRINT>(funcname,address));
		else
			cout<<grname<<" returns Null"<<endl;
		break;
	
		case 1: //EXECUTES WHEN FREE IS CALLED

		if (disable) return;
		
		for(gc_it = gcmap.begin() ; gc_it != gcmap.end() ; ++gc_it)
			if(gc_it->second == address)
				gcmap.erase (gc_it);  
		break;

		case 2: //EXECUTES AT ANY RTN ENTRY
	
		funcname1 = funcname;	
		funcname = grname;
		break;

		case 3: //Executes When REALLOC is called.

		for(gc_it = gcmap.begin() ; gc_it != gcmap.end() ; ++gc_it)
			if(gc_it->second == address)
				flag = 1;
		if(flag == 0)
			gcmap.insert(std::pair<char *,ADDRINT>(funcname,address));
		break;

		case 4: // Executes when Malloc Returns NULL
		if (address == 0)
		{
			cout<<"Return Address is: "<<address <<endl;
			cout<<"Program tried writing at that memory location, So Exiting from Program to prevent Segmentation Fault" <<endl;
			exit(1);
		}
		else
		break;			
	}
}

/* ====================================================================================================================
This analysis routine will make a call to Application's free() function and passes the un-freed addresses to free them. 
This Function Executes at the end of any Routine.
======================================================================================================================= */

VOID FreePtr(CONTEXT * ctxt, THREADID threadIndex, char *rname, ADDRINT address) // To free the garbage.
{
	disable = true;
	for(gc_it = gcmap.begin() ; gc_it != gcmap.end() ; ++gc_it)
	{
		if(*(gc_it->first) == *rname)
		{
			if(gc_it->second != address)
			{	
				cout<<"Following Garbage is been collected from:"<<endl;
				cout<<gc_it->first<<" => "<<hex<<"0x"<<gc_it->second<<endl;
				PIN_CallApplicationFunction(ctxt, threadIndex,CALLINGSTD_STDCALL, //To call Application's free() function
							(AFUNPTR) freeptr, 
							PIN_PARG(void), 
							PIN_PARG(void*),(void *) gc_it->second, 
							PIN_PARG_END() );
				gcmap.erase (gc_it);
			}
		}
	}
	for(gc_it = gcmap.begin() ; gc_it != gcmap.end() ; ++gc_it) // To change scope of garbage passed as paramter 
		if(gc_it->second == address)
		{
			gcmap.erase (gc_it);
			gcmap.insert(std::pair<char *,ADDRINT>(funcname1,address));
		}						
	disable = false;
	
}



/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */


VOID Image(IMG img, VOID *v)
{

	/* **********************************************************************************************************************
	This image is used to instrument various Memory Allocation and Deallocation functions like malloc(), calloc(), free() 
	etc and inserts call to analysis routine. Only the "libc.so" image is instrumented so that all the other available malloc() 
	and free() may not get instrumented.
	************************************************************************************************************************* */
	
	if (strstr(IMG_Name(img).c_str(), "libc.so"))
	{ 	
    		//Find the malloc() function.
    		RTN mallocRtn = RTN_FindByName(img, MALLOC);
    		if (RTN_Valid(mallocRtn))
    		{
        		RTN_Open(mallocRtn);
        		// Instrument malloc() to print the return value.
        		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)garbageRecord, IARG_ADDRINT, MALLOC,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_UINT32, 0, IARG_END);
        		RTN_Close(mallocRtn);
		}
		//Find the calloc() function.
		RTN callocRtn = RTN_FindByName(img, "calloc");
    		if (RTN_Valid(callocRtn))
    		{
        		RTN_Open(callocRtn);
        		// Instrument calloc() to print the return value.
        		RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)garbageRecord, IARG_ADDRINT, MALLOC,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_UINT32, 0, IARG_END);
        		RTN_Close(callocRtn);
		}
		//Find the new() function.
		RTN reallocRtn = RTN_FindByName(img, "realloc");
    		if (RTN_Valid(reallocRtn))
    		{
        		RTN_Open(reallocRtn);
        		// Instrument new() to print the return value.
        		RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)garbageRecord, IARG_ADDRINT, MALLOC,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_UINT32, 3, IARG_END);
        		RTN_Close(reallocRtn);
		}
	    	// Find the free() function.
    		RTN freeRtn = RTN_FindByName(img, FREE);
    		if (RTN_Valid(freeRtn))
    		{ 
        		freeptr = RTN_Funptr(freeRtn);
        		RTN_Open(freeRtn);
        		//Instrument free() to print the input argument value.
        		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)garbageRecord, 	
					IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_UINT32, 1, IARG_END);
        		RTN_Close(freeRtn);
    		}
		/*// Find the delete() function.
    		RTN deleteRtn = RTN_FindByName(img, "delete");
    		if (RTN_Valid(deleteRtn))
    		{ 
        		//freeptr = RTN_Funptr(deleteRtn);
			//printf("FREE PTR: %p\n",freeptr);
        		RTN_Open(deleteRtn);
        		//Instrument free() to print the input argument value.
        		RTN_InsertCall(deleteRtn, IPOINT_BEFORE, (AFUNPTR)garbageRecord, 	
					IARG_ADDRINT, FREE, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_UINT32, 1, IARG_END);
        		RTN_Close(deleteRtn);
    		}*/
	}

	/* *************************************************************************************************************
	This image is used to instrument main() and other user defined functions and make calls at proper juncture to the
	analysis routines to maintain the data structure which stores the memory addresses being allocated. At the end of 
	each routine being called the unallocated  memory is freed by making a call to the analysis routine which further 
	deallocates the memory.
	**************************************************************************************************************** */

	if(IMG_Id(img) == 1)
	{
		lowadd = IMG_LowAddress (img);
		highadd = IMG_HighAddress (img);
	  	
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
        		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        		{	
				
            			RTN_Open(rtn);
				name = RTN_Name(rtn);
				UINT32 flag=0;
				if (strstr(name.c_str(), "_") || strstr(name.c_str(), ".") )
					flag=1;
				if(flag==0) 
				{
					for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				        {
						if(INS_IsMemoryWrite(ins)) 
		        			 	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)garbageRecord, 
							IARG_ADDRINT, strdup(name.c_str()), IARG_MEMORYWRITE_EA, IARG_UINT32, 4, IARG_END);
		    			}
					// to find read/write at global pointer
					for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) 
				        {
						if(INS_IsMemoryRead(ins)) 
		        		 		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)globalRecord, IARG_ADDRINT, 
							strdup(name.c_str()), IARG_MEMORYREAD_EA, IARG_END);
		    			}
					RTN_InsertCall( rtn, IPOINT_BEFORE, (AFUNPTR)garbageRecord, IARG_ADDRINT, 
							strdup(name.c_str()),IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
							IARG_UINT32, 2, IARG_END
						      );	
					RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreePtr, IARG_CONTEXT, IARG_THREAD_ID, IARG_ADDRINT, 
								strdup(name.c_str()),IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
				}
            			RTN_Close(rtn);
         		}
     		}
	}

}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{  
	gcmap.clear();	
	TraceFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc and free. Un-FreedMemory is Freed after each Routine" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{   
	// Initialize pin & symbol manager
	PIN_InitSymbols();
	if( PIN_Init(argc,argv) )
	{
        	return Usage();
	}

	TraceFile.open(KnobOutputFile.Value().c_str());
	TraceFile << hex;
   	TraceFile.setf(ios::showbase);

   	// Register Image to be called to instrument functions.
   	IMG_AddInstrumentFunction(Image, 0);
   	PIN_AddFiniFunction(Fini, 0);

   	// Never returns
   	PIN_StartProgram();

  	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */




