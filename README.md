# Laplace - Shellcode-launcher

![tumblr_8db1efec2b9cd1bfb467e31b7d5c3125_bf9b9112_540](https://user-images.githubusercontent.com/82961078/146617492-fd2733d1-14c6-4b4d-aa99-13e7b0b9512f.gif)


Laplace es un launcher/Stub externo de shellcode runtime en desarrollo por un autodidacta, para el Spyware Medusa.

**¿Cómo será Laplace?**

Laplace es un proyecto recién creado, por un novato del malware avanzado con ganas de aprender sobre este mundo. Por lo tanto, debéis tener en cuenta que
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


