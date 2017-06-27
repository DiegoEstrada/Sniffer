# Sniffer
Proyecto para Redes de computadoras. A través de una interfaz gráfica, este proyecto analiza las tramas al vuelo o desde un archivo con base 
en los protocolos ETHERNET, IEEE 802.3, IP v4, TCP, ARP, UDP e ICMP, permitiendo especificar algunos filtros de captura como el tamño máximo de
paquees, el modo de captura, el tiempo de captura, el número de paquetes a recibir asi como los protocolos que se desean recibir.

Este proyecto requiere de la librerias jnetpcap 1.3 y jfreechart 1.0.19, las cuales se  encuentran en el repositorio. Además es necesaro configurar 
el arranque del proyecto, en el caso de Netbeans las opciones de la máquina virtual deben ser cambiadas por el siguiente comando. 

-Djava.library.path="DIRECCION\jnetpcap-1.3.0". Donde DIRECCION representa la ruta del archivo jnetpcap-1.0.3.

Para más información sobre la configuración visitar http://148.204.58.221/axel/redesnp/sniffer/jnetpcap/instalacion_netbeans.pdf
