#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define WM_SUBCLASS (WM_APP+1)
#define WM_UNSUBCLASS (WM_APP+2)
#define N 8
typedef struct{HWND h;HHOOK cbt;HHOOK cwp;BOOL s;}E;
static E g[N];
static HMODULE m;
static DWORD p;
static E*f(HWND h){for(int i=0;i<N;i++)if(g[i].h==h)return&g[i];return 0;}
static E*a(){for(int i=0;i<N;i++)if(!g[i].h)return&g[i];return 0;}
static void r(E*x){x->h=0;x->cbt=0;x->cwp=0;x->s=0;}
static LRESULT CALLBACK cb_cbt(int n,WPARAM w,LPARAM l){if(n>=0&&(n==HCBT_ACTIVATE||n==HCBT_SETFOCUS)){E*x=f((HWND)w);if(x&&x->s){DWORD q=0;GetWindowThreadProcessId(GetForegroundWindow(),&q);if(q!=p)return 1;}}return CallNextHookEx(0,n,w,l);}
static LRESULT CALLBACK cb_cwp(int n,WPARAM w,LPARAM l){if(n>=0){CWPSTRUCT*c=(CWPSTRUCT*)l;if(c->message==WM_SUBCLASS){E*x=f(c->hwnd);if(!x){x=a();if(x)x->h=c->hwnd;}if(x)x->s=1;}else if(c->message==WM_UNSUBCLASS){E*x=f(c->hwnd);if(x)r(x);}}return CallNextHookEx(0,n,w,l);}
__declspec(dllexport) BOOL __stdcall n(HWND h){if(!IsWindow(h))return 0;if(f(h))return 1;DWORD t=GetWindowThreadProcessId(h,0);if(!t)return 0;E*x=a();if(!x)return 0;HHOOK k=SetWindowsHookEx(WH_CBT,cb_cbt,m,t);if(!k)return 0;HHOOK q=SetWindowsHookEx(WH_CALLWNDPROC,cb_cwp,m,t);if(!q){UnhookWindowsHookEx(k);return 0;}x->h=h;x->cbt=k;x->cwp=q;x->s=0;SendMessage(h,WM_SUBCLASS,0,0);return 1;}
__declspec(dllexport) BOOL __stdcall q(HWND h){E*x=f(h);if(!x)return 0;DWORD_PTR r0=0;SendMessageTimeoutA(h,WM_UNSUBCLASS,0,0,SMTO_NORMAL|SMTO_ABORTIFHUNG,5000,&r0);if(x->cwp)UnhookWindowsHookEx(x->cwp);if(x->cbt)UnhookWindowsHookEx(x->cbt);r(x);return 1;}
BOOL APIENTRY DllMain(HMODULE h,DWORD r,LPVOID){if(r==DLL_PROCESS_ATTACH){m=h;p=GetCurrentProcessId();DisableThreadLibraryCalls(h);}return 1;}
