/*

SYSCALLS:
- ver si plicar Syscalls en las funciones CreateToolHelp32Snapshot, etcétera.

*/

#include "laplace.h"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow){
	//Verificar X86 o X64
	
	//https://stackoverflow.com/questions/2877295/get-os-in-c-win32-for-all-versions-of-win
	OSVERSIONINFOEX osver; //Estructura sobre información del sistema operativo
	ZeroMemory(&osver, sizeof(osver));
	osver.dwOSVersionInfoSize = sizeof(osver);
	
	GetVersionEx((LPOSVERSIONINFO)&osver); //Obtener el sistema operativo actual
	
	LPBYTE data = 0;
	
	if(NERR_Sucess == NetWkstaGetInfo(NULL, 100, &data)){ //Obtener información de la workstation si es el caso
		
		WKSTA_INFO_100* workstation = (WKSTA_INFO_100*)data; //Estructura con datos de la WorlStation
        osver.dwMajorVersion = workstation->wki100_ver_major; 
        osver.dwMinorVersion = workstation->wki100_ver_minor;
        //Si es Workstation, le ponemos igualmente las versiones correspondientes a un OS normal
        ::NetApiBufferFree(data); //Liberamos lo que ya no necesitamos
		}
	
	/*
	Diferenciar Windows 8 de Windows 8.1, realmente no sirve para este contexto, pero lo dejo por si alguien quiere implementarlo
	else if(osver.dwMajorVersion == 6 && osver.dwMinorVersion == 2){ //diferenciar Windows 8 de 8.1
		OSVERSIONINFOEX osvi;
		ZeroMemory(&osvi, sizeof(osvi));
		osvi.dwOSVersionInfoSize = sizeof(osvi);
        osvi.dwMinorVersion = 3; 
		ULONGLONG sv = 0;
		
		sv = VerSetConditionMask(sv, VER_MINORVERSION, VER_EQUAL); 
        if(VerifyVersionInfo(&osvi, VER_MINORVERSION, vm) osver.dwMinorVersion = osvi.dwMinorVersion = 3;
		}
       */
	
    if(osver.dwMajorVersion < 6){
    	Exit(1);
    	}
    }
	
	
	
	if(CHECK_VM()){
		Exit(1);
		}
    }

static BOOL CHECK_VM(){
	
	int gb_size = 257;
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED); //Inicialización de la biblioteca COM para ser usada por el subproceso que haga la llamada. La simultaneidad Multi-threading (también llamado free-threading) permite que las llamadas a métodos de objetos creados por este hilo se ejecuten en cualquier hilo. No hay serialización de llamadas, es decir, pueden ocurrir muchas llamadas al mismo método
    //Hay que configurar las llamadas a la WMI
	
	if(FAILED(hres)) goto check_vmprocess;
	
	//Inicialización para la seguridad del proceso COM. 
	hres =  CoInitializeSecurity(
    NULL, //Permisos que necesita un servidor para recibir llamadas
    -1,   //COM elige servicio de autentificación al recibir las llamadas. Schannel (Paquete de seguridad que admite ciertos protocolos seguros) no será usado                    
    NULL, //Autentificaciones que el servidor usará                     
    NULL,   //Siempre es NULL                     
    RPC_C_AUTHN_LEVEL_DEFAULT, //Parámetro usado por el cliente, el nivel de autentificación lo eligirá COM, y eligirá la manta de seguridad adecuada
    RPC_C_IMP_LEVEL_IMPERSONATE, //Nivel de suplantación, usado por el cliente. Elegido por COM. Siempre tendrá el nivel de suplantación asociado.
    NULL, //Lista de nuestras autentificaciones escogidas cuando COM elige el nivel.                  
    EOAC_NONE, //Ninguna capacidad              
    NULL //Siempre es NULL                   
    );
	
	if(FAILED(hres)){ CoUninitialize(); goto check_vmprocess;}
	
	IWbemLocator *loc = NULL; //Objeto COM en proceso. Interfaz para obtener el puntero a la interfaz para acceder a WMI
	
	hres = CoCreateInstance( //Obtener el localizador antes mencionado, creando un objeto asociado a la CLSID
     CLSID_WbemLocator,  //Código asociado para la creación del objeto       
    0, //Objeto no creado por parte de un agregado.
    CLSCTX_INPROC_SERVER, //Contexto donde operará este objeto. Se ejecutará en el mismo proceso que el que llamó la función creadora del contexto
    IID_IWbemLocator, (LPVOID *) &loc); //Interfaz puntero de la interfaz que nos brindará acceso a la WMI
    
    if(FAILED(hres)){ CoUninitialize(); goto check_vmprocess;}
    
    IWbemServices *svc = NULL; //Interfaz que nos permitirá acceder a la WMI
    
    int timer = GetTickCount();
    
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WAIT_SVTIME, timer, 0, NULL); 
    
    hres = loc->ConnectServer(//Ahora el objeto debe conectarse al namespace deseado de la WMI (clases sobre hardware principalmente) 
    _bstr_t(L"ROOT\\CIMV2"), //namespace de WMI donde queremos acceder
    NULL,  //Username actual del cliente               
    NULL, //Contraseña: Contexto actual                   
    0, //Configuración regional actual              
    0,  //Acceso al servidor cuando sea posible.               
    0, //Usuario actual a autentificar                  
    0,  //Este valor en este contexto casi siempre es nulo                    
    &svc  //Puntero vinculado a la interfaz de acceso a WMI           
     );
     
     PGLOB->CON_REALIZED = TRUE;
     
     
     if(FAILED(hres)){ loc->Release();CoUninitialize(); goto check_vmprocess;}
     
     hres = CoSetProxyBlanket(//Inicialización de la seguridad del proxy creado para que WMI tome el papel del cliente en la consulta al namespace
     svc,  //Proxy que se establecerá                  
     RPC_C_AUTHN_WINNT, //Para la autentificación, se usará el conjunto de protocolos  NTLM, donde el cliente se tiene que autentificar con username y pass
     RPC_C_AUTHZ_NONE,  //Para que NTLM pueda ser usado     
     NULL, //Nombre por defecto del servidor y su respectiva configuración           
     RPC_C_AUTHN_LEVEL_CALL, //Inicia la autentificación cuando se envía la solicitud
     RPC_C_IMP_LEVEL_IMPERSONATE, //Nivel de suplantación, para los protocolos NTLM
     NULL,  // Identidad del proxy actual                 
     EOAC_NONE //Ninguna capacidad extra para este proxy              
    );
    
    if(FAILED(hres)){ loc->Release();svc->Release();CoUninitialize(); goto check_vmprocess;}
    
    IEnumWbemClassObject* _enum = NULL; //Interfaz para enumerar los componentes WMI
    hres = svc->ExecQuery(//Ejecutar nuestra solicitud
    bstr_t("WQL"), //Solicitamos los datos con el lenguaje de consulta WMI
    bstr_t("SELECT * FROM Win32_DiskDrive"), //Solicitamos datos de la clase sobre el disco duro
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, //Optimizar la búsqueda
    NULL, 
     _enum); //Donde almacenaremos la consulta
    
    if(FAILED(hres)){_enum->Release(); loc->Release();svc->Release();CoUninitialize(); goto check_vmprocess;}
    
    IWbemClassObject *obj = NULL;
    
    
    ULONG _rvalue = 0;
    HRESULT hr;
    while(_enum){ //Recorremos los datos obtenidos
    	hr = _enum->Next(WBEM_INFINITE, 1, &obj, &_rvalue); //Los recorremos uno por uno
        if(_rvalue == 0) break;
    	}
    VARIANT val;
    
    hr = obj->Get("Size", 0, &val, 0, 0); //Obtenemos el tamaño aproximado en bytes del Disco Duro
    
    if(SUCCEEDED(hr)) hr = VariantChangeType(&val, &val, 0, VT_I4);
    else return TRUE;
    
    long byte_size = val.lVal; 
    gb_size = round(byte_size/1024/1024/1024); //Pasamos de bytes a gigabytes
    VariantClear(&val);
	_enum->Release();loc->Release();svc->Release();obj->Release();CoUninitialize();
	
    check_vmprocess:
    if(gb_size > 256){ //Las máquinas virtuales no suelen superar los 256 GB
    	const char *pname[] = {}; // Nombre de los procesos encriptados 
        
        //Trataremos de obtener el PID de los procesos de las máquinas virtuales, si nos devuelve uno, significa que está presente uno de los procesos
        
    	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        DWORD pid = 0;
        PROCESSENTRY32 pe;
        if(snap == INVALID_HANDLE_VALUE) return TRUE;
        pe.dwSize = sizeof(pe);
        BOOL ps = Process32First(snap, &pe);
        while(ps){
        	for(int i = 0; i < sizeof pname/sizeof pname[0]; i++){
        	    if(strcmp((char*)pe.szExeFile,pname[i]) == 0){
         	        pid = pe.t32ProcessId;
         	    }
                 else{
                     ps = Process32Next(snap, &pe);
                    }
        	    }
            CloseHandle(snap);
            }
        if(pid != 0) return TRUE;
        else{
        	BOOL SOME_BOOLEAN = CHECK_SPEC_VM_INFO();
            if(SOME_BOOLEAN) return TRUE;
        	}
        }
    //Si algo de esto no llega a ser suficiente, tendríamos que analizar en memoria para encontrar los procesos
    return FALSE;
	}
	
	
	

/*
DESCRIPCIONES de la función CHECK_VM:

WMI: Una especie de base de datos con clases con información sobre hardware y el sistema operativo.

Componente de software: Partes del software que ofrecen o solicitan un conjunto de funcionalidades.

Módulo de un programa: Partes del software

Interfaz Binaria: Bajo nivel de la interfaz entre un programa y el sistema operativo. 
Los ABI cubren detalles como el tipo de datos, el tamaño y la alineación; la llamada
convención, que controla cómo se pasan los argumentos de las funciones y valores de retorno recuperados; 
los números de llamada del sistema y cómo una   la aplicación debe hacer llamadas al sistema operativo.

La interfaz:  es el medio con que el programa puede comunicarse con una máquina, equipo, computadora o dispositivo, y comprende todos los puntos de contacto entre el programa y el equipo.

Por lo que: COM es una ABI estandarizada en Windows, que permite la comunicación entre procesos (En este caso, WMI) 
Básicamente, para lograr integrar los componentes del software con terceras partes (como librerías, entre otros) se debe
realizar un sistema común para conseguirlo. 

Constantes de autentificación:

- Son niveles de autentificación para el cliente. Son varios niveles de protección, desde nada hasta cifrado extremo.
Nivel de suplantación (Constantes de autenticación):

- Niveles de autoridad que se le da al servidor cuando suplanta/delega el cliente. Por eso se está usando un servidor Proxy (Perteneciente a WMI).
Por que se llegan a necesitar? Esta es una técnica en la que un proceso o sistema debe utilizar las credenciales de otro principal de seguridad, en lugar de su propio contexto de seguridad, para conectarse a un recurso.
Por ejemplo, un servicio debe realizar una función en nombre de otra cuenta (por ejemplo, en nombre del usuario actual que inició sesión en la computadora). En este caso, el servicio necesita crear un token de acceso especial
que describa el contexto de seguridad de la cuenta bajo la cual queremos realizar la acción especificada. Para crear dicho token de acceso, el servicio necesita conocer las credenciales de este usuario y, si este proceso ocurre en
 la máquina local, obtener una copia del token de acceso del usuario local previamente registrado. 
 
 Fuente (página que explica muy bien sobre este tema) https://tech-es.netlify.app/articles/es537560/index.html


Negociación de seguridad (Niveles predeterminados) 
Medidas de seguridad que se le da al Proxy de una interfaz (comunicación entre dos softwares, como obtener información de WMI)
COM compara los niveles de seguridad y crea una medida de seguridad para la llamada/subproceso COM para el proxy. Por eso los clientes deben tener las medidas inicializadas.
La seguridad de ambos lados reside en los mantos de seguridad.

- Todos estos niveles de seguridad definen el proceso de COM. A veces la seguridad es necesaria para acceder a WMI, al menos en valores mínimos, según los permisos otorgados a este proceso.
por ejemplo, si un proceso no tiene permisos para borrar un archivo, con WMI tampoco. Aquí es donde actúa COM, para establecer la conexión según los privilegios a WMI.
El token de acceso es generado por el SID (id único para un usuario de windows) y contiene los grupos a los que pertenece, sus privilegios, y los procesos que inicia) nuestros procesos tienen objetos de seguridad, que almacena el control de acceso
ACL para el token. Cuando un proceso ejecutado por el usuario accede a un objeto, el token de acceso se compara con el ACL, y ahí, otorga o no los privilegios. El mecanismo de seguridad de WMI sigue esta regla de Windows, y cada namespace puede tener su propio descriptor de seguridad 
donde almacena el ACL. Las entradas de control de acceso contiene información sobre los permisos cuando realiza operaciones en el namespace
el proceso accede a WMI mediante utilidades especiales y actúa como cliente, y el objeto WMI al que se accede es el servidor. Los niveles de suplantación de DCOM estándar se utilizan para determinar qué token de acceso se utilizará cuando se trabaja con WMI en una computadora remota (No es este caso)


Indicadores de capacidad:

Capacidades adicionales para el cliente o el servidor

Clave CLSID: Identificador que identifica un componente de software en una aplicación.

El servidor proxy en este contexto es el objeto WMI para acceder a sus servicios. 

El protocolo NTLM(SSP) también negocia el nivel de seguridad (autentificación para seguridad WMI con username y pass), por eso es usado. 
Puede ser usado tanto en la capa 2-3 WMI (PC Local sin conexión a la red) tanto en la capa 3 y 2 (Conexión remota desde el PC cliente al PC remoto objetivo) para conexión 
remota. Esta diseñado para ambos contextos
MÁS INFORMACIÓN : https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/c0088a94-1107-48a5-8d4d-cd16d34de5ef

Las aplicaciones cliente y los scripts que acceden a proveedores estándar de WMI de 32 bits siguen funcionando con normalidad cuando se ejecutan en un sistema operativo de 64 bits. 
Solo dos proveedores preinstalados, el proveedor del Registro del sistema y el proveedor de vistas ,tienen versiones de 64 bits que se ejecutan en paralelo con las versiones de 32 bits. 
Sin embargo, una aplicación de 32 bits que solicita instancias de Windows Driver Model (WDM) de 32 bits recibe las instancias predeterminadas de la clase WDM de 64 bits en un sistema operativo de 64 bits.
*/



static DWORD WINAPI WAIT_SVTIME(LPVOID lpstart){
	int start_time = (int)lpstart;
	while(GetTickCount() - start_time < 60000){
		if(PGLOB->CON_REALIZED) ExitThread(1);
		Sleep(10);
		}
		Exit(1);
	}
static BOOL CHECK_SPEC_VM_INFO(){
	
	//OBTENER LAS MAC DE LA VM, SI NO FUERON CAMBIADAS, FUNCIONARÁ
    BOOL ANY_EXEC_CHECK = FALSE;

	PIP_ADAPTER_INFO adapter; //Estructura con información sobre networks adapters
    ULONG BUFF = sizeof(IP_ADAPTER_INFO); //Buffer por si hay una excepción
             
     char *MAC = (char *)HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS,24); //Reservamos memoria para almacenar la MAC
     CHECK_ALLOC_ERROR(1,0, MAC);
     adapter = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(IP_ADAPTER_INFO));
     CHECK_ALLOC_ERROR(2,1,adapter);
     if(GetAdaptersAdresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, NULL, adapter, &BUFF) == ERROR_BUFFER_OVERFLOW){ //Si el buffer inicial no es suficiente
     	HeapFree(GetProcessHeap(),0, adapter);
         adapter = (IP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, BUFF);
         CHECK_ALLOC_ERROR(2,1,adapter);
         //Cambiamos el tamaño del buffer al tamaño necesario
     	}
     if(GetAdaptersAdresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, NULL, adapter, &BUFF) == NO_ERROR){ //Si ya no hay errores
     	PIP_ADAPTER_INFO P_adapter = adapter;
         int three_pos = 0;
     	do{
     	    three_pos++; //La MAC de VM tiene 3 bloques con dos dígitos hexadecimal con 4 bytes cada uno. 8x3 = 24 Bytes
             sprintf(MAC, "%02X:%02X:%02X",P_adapter->Address[0], P_adapter->Address[1], P_adapter->Address[2]);
             P_adapter = P_adapter->Next;
             }while(P_adapter || three_pos < 3);
          HeapFree(GetProcessHeap(), 0, adapter);
     	}
     else{
     	HeapFree(GetProcessHeap(), 0, adapter);
         goto next_vmware_check1;
     }
     const char* mac_blacklist{"00:05:69", "00:0c:29" , "00:1C:14" , "00:50:56", "08:00:27"}; //ENCRIPTAR DIRECCIONES MAC
     for(int i = 0; i < sizeof(mac_blacklist) / sizeof(mac_blacklist[0];i++){
     	if(strcmp(MAC, mac_blacklist[i].c_str()) == 0) return TRUE;
     	}
    HeapFree(GetProcessHeap(),0,MAC);
    next_vmware_check1:
    
	}
void CHECK_ALLOC_ERROR(int arg, short DATA_TYPE_ID, ...){
	//Controlamos los errores de memoria
	LinkedList<void *> lista;
	va_list vl;
	va_start(vl,arg);
	for(int i = 0; i <=arg; i++){
		switch(i){
		case 0: ;
		    lista.add((void *)va_arg(vl, char *));
		    break;
		
		case 1: ;
		    lista.add((void *)va_arg(vl, IP_ADAPTER_INFO *));
		    break;
		case 2: ;
		    lista.add((void *)va_arg(vl, HANDLE));
		    break;
		    }
		
		}
	va_end(vl);
	switch(DATA_TYPE_ID){
		case 0: ;
	        if((char *)lista[DATA_TYPE_ID] == NULL){
		        HeapFree(GetProcessHeap(), 0, (char *)lista[DATA_TYPE_ID]);
		        Exit(1);
			}
		case 1: ;
		    if((IP_ADAPTER_INFO * )lista[DATA_TYPE_ID] == NULL){
			    HeapFree(GetProcessHeap(),0,(IP_ADAPTER_INFO *)lista[DATA_TYPE_ID]);
			    Exit(1);
		case 2: ;
			if((HANDLE)lista[DATA_TYPE_ID] == INVALID_HANDLE_VALUE){
				CloseHandle((HANDLE)lista[DATA_TYPE_ID]);
				Exit(1);
				}
			}
		}
	}
