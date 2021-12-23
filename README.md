# Laplace - Shellcode-launcher

![Polish_20211223_094627019](https://user-images.githubusercontent.com/82961078/147214000-b6e7d40c-a7d9-4196-89e0-f3fd377d0f88.jpg)


Laplace es un launcher/Stub externo de shellcode runtime en desarrollo por un autodidacta, para el Spyware Medusa.

**¿Cómo será Laplace?**

Laplace es un proyecto (PoC malware) recién creado, por un novato del malware avanzado con ganas de aprender sobre este mundo. Por lo tanto, debéis tener en cuenta que
este launcher ha sido creado por un novato, que está aprendiendo mientras desarrolla su proyecto.

Por ahora, este launcher planteará lo siguiente:

- Stub indenpendiente del crypter. El stub será externo, por lo que el crypter no estará presente en la infección

- Stub runtime: Este stub no debe ser detectado por los antivirus mientras sea ejecutado

- Bypass VM: No es deseado que Laplace sea ejecutado en una máquina virtual para ser expuesto a debugs, análisis de memoria forense, Ingenieria inversa u otros análisis.

- Bypass EDR: no es deseado que los EDR de los antivirus detecten las llamadas maliciosas para inyectar código o para otras actividades sospechosas. Serán usadas principalmente "Syscalls", a pesar de su inestabilidad

- Bypass AMSI: El Launcher tratará de no tocar disco ni tocar lo que más analiza el antivirus (Fileless), y tratar de bypassear el AMSI para que esto pueda ser realizado con éxito.

- Process Hollowing: Técnica RunPE elegida por ahora para la inyección de código

- Persistencia: Encontrar una manera no sospechosa de que Laplace pueda ser iniciado junto al sistema operativo para volver a cargar el payload

- Bind en ejecutable legítimo: Para que el usuario no sospeche

- Encripción de strings y descifrado del shellcode encriptado

- API Hashing: Para que a los investigadores les cueste más investigar las APIs llamadas

- Y mucho más que puede venir en las próximas actualizaciones, cuando termine de estudiar sobre este tema ;-)

**Estado actual [17 de Diciembre de 2021]**

Se está desarrollando un Bypass VM sin tener en cuenta todo lo anteriormente dicho, ya que no se necesitan conocimientos especiales para detectar una máquina virtual. Tened paciencia, todo será implementado un día.

**Requisitos de ejecución**

- Windows Vista o superior
- Por ahora, arquitectura de 32 bits

**Como compilar en Visual Studio**

-Próximamente


**Contacto**

Si necesitas ayuda, o tienes un aporte, puedes escribirme en Discord. Tolaju#0001 [O cuando se me acabe el Nitro] Tolaju#2311

Mi canal de YouTube: https://youtube.com/c/Tolaju

Twitter: https://www.twitter.com/Tolaju

Telegram:

https://t.me/Tolaju


