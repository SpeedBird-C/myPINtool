#include <stdio.h>  
#include "pin.H"   
#include <iostream>
namespace WINDOWS
{
#include <windows.h>  
}

FILE* OutTrace;
ADDRINT ExceptionDispatcher = 0;
#define LAST_EXECUTED 1000  
ADDRINT LastExecutedBuf[LAST_EXECUTED];
UINT32 LastExecutedPos;
ADDRINT CurrentModuleBase, CurrentModuleEnd;
static std::map<ADDRINT, std::string> str_of_ins_at;

VOID OnException(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 info, VOID* v)
{
     if (reason != CONTEXT_CHANGE_REASON_EXCEPTION)
          return;
     UINT32 exceptionCode = info;
     ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
     if ((exceptionCode >= 0xc0000000) && (exceptionCode <= 0xcfffffff))
     {
          std::cerr << "Hellow there, Mr.Exception!";
          std::string ins_str = str_of_ins_at[address];
          std::cerr << ins_str << std::endl;
          //TODO: Here you write log, inform server!
          PIN_ExitProcess(-1);
     }
}

bool IsModuleFound(ADDRINT Addr)
{
     for (IMG Img = APP_ImgHead(); IMG_Valid(Img); Img = IMG_Next(Img))
     {
          if (Addr >= IMG_LowAddress(Img) &&
               Addr <= IMG_HighAddress(Img))    // <=, not <  
          {
               CurrentModuleBase = IMG_LowAddress(Img);
               CurrentModuleEnd = IMG_HighAddress(Img);
               return true;
          }
     }

     return false;
}

void CheckEipModule(ADDRINT AddrEip)
{
     int i;
     if (!(AddrEip >= CurrentModuleBase && AddrEip < CurrentModuleEnd))
     {
          if (!IsModuleFound(AddrEip))
          {
               // eip is no within an executable image!  
               fprintf(OutTrace, "EIP detected not within an executable module: %08x \n", AddrEip);
               fprintf(OutTrace, "Dumping list of previously executed EIPs \n");
               for (i = LastExecutedPos; i < LAST_EXECUTED; i++)
               {
                    fprintf(OutTrace, "%08x \n", LastExecutedBuf[i]);
                    if (LastExecutedBuf[i] == 0x76678d4a)
                    {
                         std::string ins_str = str_of_ins_at[AddrEip];
                         std::cerr << ins_str << std::endl;
                         WINDOWS::ExitProcess(0);
                    }
               }
               for (i = 0; i < LastExecutedPos; i++)
               {
                    fprintf(OutTrace, "%08x \n", LastExecutedBuf[i]);
                    if (LastExecutedBuf[i] == 0x76678d4a)
                    {
                         std::string ins_str = str_of_ins_at[AddrEip];
                         std::cerr << ins_str << std::endl;
                         WINDOWS::ExitProcess(0);
                    }
               }
               fprintf(OutTrace, "%08x \n --- END ---", AddrEip);
               fflush(OutTrace);
               if (LastExecutedBuf[i] == 0x76678d4a)
               {
                    std::string ins_str = str_of_ins_at[AddrEip];
                    std::cerr << ins_str << std::endl;
                    WINDOWS::ExitProcess(0);
               }
               
          }
     }

     LastExecutedBuf[LastExecutedPos] = AddrEip;
     LastExecutedPos++;
     if (LastExecutedPos >= LAST_EXECUTED)
     {
          // circular logging  
          LastExecutedPos = 0;
     }
}
/* ===================================================================== */
/* Instrumentation functions                                             */
/* ===================================================================== */

VOID DetectEip(ADDRINT AddrEip)
{
     if (AddrEip == ExceptionDispatcher)
     {
          //fprintf(OutTrace, "%08x Exception occurred!\n", AddrEip);
          std::string ins_str = str_of_ins_at[AddrEip];
          std::cerr << ins_str<<std::endl;
          std::cerr <<std::hex <<AddrEip;
     }

     CheckEipModule(AddrEip);

     // Here you can call the functions that we will add
     //(you should also remove the next line to avoid tracing every instruction being executed)

     //fprintf(OutTrace, "%08x \n", AddrEip);
}

// Pin calls this function every time a new instruction is encountered  
VOID Instruction(INS Ins, VOID* v)
{
     str_of_ins_at[INS_Address(Ins)] = INS_Disassemble(Ins);

     // Insert a call to DetectEip before every instruction, and pass it the IP  
     //INS_InsertCall(Ins, IPOINT_BEFORE, (AFUNPTR)DetectEip, IARG_INST_PTR, IARG_END);
    
    
}

VOID ImageLoad(IMG Img, VOID* v)
{
     fprintf(OutTrace, "Loading module %s \n", IMG_Name(Img).c_str());
     fprintf(OutTrace, "Module Base: %08x \n", IMG_LowAddress(Img));
     fprintf(OutTrace, "Module end: %08x \n", IMG_HighAddress(Img));
     fflush(OutTrace);
}

/* ===================================================================== */
/* Finalization function                                                 */
/* ===================================================================== */

// This function is called when the application exits  
VOID Fini(INT32 code, VOID* v)
{
     fprintf(OutTrace, "Terminating execution\n");
     fflush(OutTrace);
     fclose(OutTrace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
     PIN_ERROR("Init error\n");
     return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
     OutTrace = fopen("itrace.txt", "wb");

     WINDOWS::HMODULE hNtdll;
     hNtdll = WINDOWS::LoadLibrary("ntdll");
     ExceptionDispatcher = (ADDRINT)WINDOWS::GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
     fprintf(OutTrace, "Exception handler address: %08x \n", ExceptionDispatcher);
     WINDOWS::FreeLibrary(hNtdll);

     // Initialize pin  
     if (PIN_Init(argc, argv))
     {
          Usage();
     }

     // Register Instruction to be called to instrument instructions  
     INS_AddInstrumentFunction(Instruction, 0);
     PIN_AddContextChangeFunction(OnException, 0);

     // Register ImageLoad to be called at every module load  
     //IMG_AddInstrumentFunction(ImageLoad, 0);

     // Register Fini to be called when the application exits  
     PIN_AddFiniFunction(Fini, 0);

     // Start the program, never returns  
     fprintf(OutTrace, "Starting Pintool\n");
     PIN_StartProgram();

     return 0;
}