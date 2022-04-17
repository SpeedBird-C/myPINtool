using namespace std;
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <cstdlib>
#include <vector>
#include "pin.H"

using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;
using std::hex;
static std::ofstream out; 
std::vector<unsigned int> stack;
bool flagShadow = 0;

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "saveitTest.out", "trace file");
KNOB< BOOL > KnobPid(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "append pid to output");


//bool check_boundaries2(UINT32 );
bool check_if_system_dll(VOID* ip, UINT32 size)
{
     UINT8 opcodeBytes[15];
     UINT32 fetched = PIN_SafeCopy(&opcodeBytes[0], ip, size);

     if (fetched != size) {
          out << (unsigned long)ip << "error fetching instruction at address 0x%lx";
          return 1;
     }
     
     
     if (opcodeBytes[0] == 0xe8)
     {
          switch (opcodeBytes[2])
          {
          case 0x6e:
               return 1;
               break;
          case 0x6d:
               return 1;
               break;
          case 0x6c:
               return 1;
               break;
          case 0x8:
               return 1;
               break;
          case 0x6b:
               return 1;
               break;
          case 0x6f:
               return 1;
               break;
          default:
               return 0;
          }
     }
     return 0; 

     

}

VOID call_ins_call(ADDRINT ip, UINT32 size) {
     if ( !check_if_system_dll(reinterpret_cast<VOID*>(ip), size) )
     {
          //if (ip % 10000 == 3947)
          //{
          //     //for debug purpose
          //     printf("%p", ip);
          //}
          // помещаем в стек
          UINT32 next_eip = ip + size;
          stack.push_back(next_eip);
     }
     
     
}

VOID ret_ins_call(CONTEXT* ctxt) {
     VOID* current_esp = (VOID*)PIN_GetContextReg(ctxt, REG_STACK_PTR);
     UINT32 current_eip = (UINT32)(*(int*)current_esp);
     if (stack.size() > 0) {
          // извлекаем и сравниваем
          UINT32 original_ret_value = (UINT32)stack.back();
          stack.pop_back();
          if (original_ret_value != current_eip) {

               cout << "control flow jacking is happening due to buffer overflow" << endl;
               
               exit(1);
          }
     }
     else {
         // cout << "stack is empty" << endl;
     }

}
static UINT32 consecutiveBasicBlockscount = 0;
//------------------------------------------------------------------------------------------ 
// This function is called before every block
VOID docount()
{
     out << endl;
     out << endl;
     out << "Inc Consecutive Basic Block Counter From " << consecutiveBasicBlockscount << "\tto " << consecutiveBasicBlockscount + 1 << endl;
     out << "----------------------------------------------------------------------------------------" << endl;
     consecutiveBasicBlockscount += 1;
}
bool check_str( char* s,  char* p)
{
     char* rs = 0, * rp;
     while (1)
          if (*p == '*')
               rs = s, rp = ++p;
          else if (!*s)
               return !*p;
          else if (*s == *p || *p == '?')
               ++s, ++p;
          else if (rs)
               s = ++rs, p = rp;
          else
               return false;
}
//bool check_boundaries2(UINT32 next_eip)
//{
//     char string_address[256] = "\0";
//     char compare_to[50] = "7???????";
//     sprintf(string_address, "%x", next_eip);
//
//     if (check_str(string_address, compare_to))
//     {
//          //stack.pop_back();
//          return 1;
//     }
//     else
//     {
//          return 0;
//     }
//
//}
bool check_boundries(BBL bbl)
{
     char string_address[256]="\0";
     char compare_to[50] = "*?1447";
     sprintf(string_address, "%x", BBL_Address(bbl));


    
     if (check_str(string_address, compare_to))
     {
          flagShadow = 1;
          return 1;
     }
     else 
     {
          return 0;
     }
}
bool check_upper_boundaries(BBL bbl)
{
     char string_address[256] = "\0";
     char compare_to[50] = "7???????";
     sprintf(string_address, "%x", BBL_Address(bbl));

     if (check_str(string_address, compare_to))
     {
          return 0;//1;
     }
     else
     {
          return 1; // 0;
     }

}
VOID dump(VOID* ip, UINT32 size)
{
     unsigned int i;
     UINT8 opcodeBytes[15];

     UINT32 fetched = PIN_SafeCopy(&opcodeBytes[0], ip, size);

     if (fetched != size) {
          //fprintf(trace, "*** error fetching instruction at address 0x%lx", (unsigned long)ip);
          out << (unsigned long)ip << "error fetching instruction at address 0x%lx";
          return;
     }
     out << "\n";
     //fprintf(trace, "\n");
     out << "\n" << size << endl;
     //fprintf(trace, "\n%d\n", size);

     for (i = 0; i < size; i++)
          //fprintf(trace, " %02x", opcodeBytes[i]); //print the opcode bytes
          out << " " << hex << static_cast<int>(opcodeBytes[i]);
     out << endl;

     //fprintf(trace, " %02x", opcodeBytes[i]); //print the opcode bytes
// fflush(trace);
}
bool check_lower_bound(BBL bbl)
{
     char string_address[256] = "\0";
     char compare_to[50] = "*?1581";
     sprintf(string_address, "%x", BBL_Address(bbl));

     //cerr << string_address << endl;

     if (check_str(string_address, compare_to))
     {
          flagShadow = 0;
          return 1;
     }
     else
     {
          return 1;
     }
}

//VOID ImageLoad(IMG  img, VOID* v)
//{
VOID Trace(TRACE trace, VOID* v)
{
     
     for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
     {
          if ((flagShadow == 1 || check_boundries(bbl)) && check_upper_boundaries(bbl) && check_lower_bound(bbl) )
          {
               out << "*****" << "Adr " << hex << BBL_Address(bbl) << "*****" << endl;
               out << hex << dec;
               for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
               {
                    out << INS_Disassemble(ins) << endl;
                   
               }
               out << "********************************" << endl;

               //BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);

               for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
               {
                    //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dump, IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_END);
                    //  инструкция вызова
                    if (INS_IsCall(ins)) {
                         UINT32 size = INS_Size(ins);
                         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)call_ins_call,
                              IARG_INST_PTR,
                              IARG_UINT32, size,
                              IARG_END);
                    }
                    // инструкция ret
                    if (INS_IsRet(ins)) {
                         INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ret_ins_call, IARG_CONTEXT, IARG_END);
                    }


               }
          }

          
     }
     
     
}


// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
     cout << "Over" << endl;
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
     cerr << "This tool is used to detect control flow jacking" << endl;
     return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
     // Initialize symbol process
     PIN_InitSymbols();
     // Initialize pin
     if (PIN_Init(argc, argv)) {
          return Usage();
     }
     string filename = KnobOutputFile.Value();

     if (KnobPid)
     {
          filename += "." + decstr(getpid());
     }

     // Do this before we activate controllers
     out.open(filename.c_str());
     //out << hex << right;
     //out.setf(ios::showbase);
     // Register ImageLoad to be called to instrument instructions
     //IMG_AddInstrumentFunction(ImageLoad, 0);
     TRACE_AddInstrumentFunction(Trace, 0);

     // Register Fini to be called when the application exits
     PIN_AddFiniFunction(Fini, 0);

     // Start the program, never returns
     PIN_StartProgram();

     return 0;
}