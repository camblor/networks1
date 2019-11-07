'''
    arp.py
    Implementacion del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''



from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

#Semaforo global 
globalLock =Lock()
#Direccion de difusion (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP comun a peticiones y respuestas. Especifica para la combinacion Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera comun ARP
ARP_HLEN = 6

#Variable que alamacenara que direccion IP se esta intentando resolver
requestedIP = None
#Variable que alamacenara que direccion MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que alamacenara True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la cache
cacheLock = Lock()
#Cache de ARP. Es un diccionario similar al estandar de Python solo que eliminara las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)

#struct - Interpret bytes as packed binary data
ARPRequestCode = struct.pack("!H", 1)
ARPReplyCode = struct.pack("!H", 2)


'''
    Nombre: getIP
    Descripcion: Esta funcion obtiene la direccion IP asociada a una interfaz.
    Esta funcion NO debe ser modificada
    Argumentos:
        -interface: nombre de la interfaz
    Retorno: Entero de 32 bits con la direccion IP de la interfaz
'''
def getIP(interface):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]

'''
    Nombre: printCache
    Descripcion: Esta funcion imprime la cache ARP
    Argumentos: Ninguno
    Retorno: Ninguno
'''
def printCache():

    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))


'''
    Nombre: processARPRequest
    Decripcion: Esta funcion procesa una peticion ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
        -Extraer la MAC origen contenida en la peticion ARP
        -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
        -Extraer la IP origen contenida en la peticion ARP
        -Extraer la IP destino contenida en la peticion ARP
        -Comprobar si la IP destino de la peticion ARP es la propia IP:
            -Si no es la propia IP retornar
            -Si es la propia IP:
                -Construir una respuesta ARP llamando a createARPReply (descripcion mas adelante)
                -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
    Argumentos:
        -data: bytearray con el contenido de la trama ARP (despues de la cabecera comun)
        -MAC: direccion MAC origen extraida por el nivel Ethernet
    Retorno: Ninguno
'''
def processARPRequest(data,MAC):

    # Extraccion de la mac origen
    macOrigenContenida = data[8:14]
    # Mac origen no es la misma -> retornar
    if macOrigenContenida != MAC:
	    return

    # Extraccion de ip origen-destino
    ipOrigenContenida = struct.unpack("!I", data[14:18])[0]
    ipDestinoContenida = struct.unpack("!I", data[24:28])[0]


    # ip Destino no es la nuestra -> retornar
    if ipDestinoContenida != myIP:
        return

    # Creacion y envio de respuesta
    respuestaARP = createARPReply(ipOrigenContenida, macOrigenContenida)
    sendEthernetFrame(respuestaARP, len(respuestaARP), 0x0806, bytes(macOrigenContenida))
    

'''
    Nombre: processARPReply
    Decripcion: Esta funcion procesa una respuesta ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
        -Extraer la MAC origen contenida en la peticion ARP
        -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
        -Extraer la IP origen contenida en la peticion ARP
        -Extraer la MAC destino contenida en la peticion ARP
        -Extraer la IP destino contenida en la peticion ARP
        -Comprobar si la IP destino de la peticion ARP es la propia IP:
            -Si no es la propia IP retornar
            -Si es la propia IP:
                -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                -Copiar la MAC origen a la variable global resolvedMAC
                -Añadir a la cache ARP la asociacion MAC/IP.
                -Cambiar el valor de la variable awaitingResponse a False
                -Cambiar el valor de la variable requestedIP a None
    Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la funcion ARPResolution y deben ser protegidas mediante un Lock.
    Argumentos:
        -data: bytearray con el contenido de la trama ARP (despues de la cabecera comun)
        -MAC: direccion MAC origen extraida por el nivel Ethernet
    Retorno: Ninguno
'''
def processARPReply(data,MAC):
    global requestedIP,resolvedMAC,awaitingResponse,cache

    # Extraemos la MAC
    macOrigenContenida = data[8:14]

    # MAC origen no es la misma
    if macOrigenContenida != MAC:
        return

    # Extraemos ip origen-destino
    ipOrigenContenida = struct.unpack("!I", data[14:18])[0]
    ipDestinoContenida = struct.unpack("!I", data[24:28])[0]
   
    # comprobacion si se corresponde la IP
    if ipDestinoContenida != myIP:
        return


    # INICIO - GLOBAL LOCK
    with globalLock:
        # No buscabamos esta IP -> retornar
        if not ipOrigenContenida == requestedIP:
	        return
    
    
        resolvedMAC = macOrigenContenida

        # INICIO - CACHE LOCK
        with cacheLock:
            cache[requestedIP] = resolvedMAC
        # FIN - CACHE LOCK

        awaitingResponse = False
        requestedIP = None
    # FIN - GLOBAL LOCK

    
    

'''
    Nombre: createARPRequest
    Descripcion: Esta funcion construye una peticion ARP y devuelve la trama con el contenido.
    Argumentos: 
        -ip: direccion a resolver 
    Retorno: Bytes con el contenido de la trama de peticion ARP
'''
def createARPRequest(ip):
    global myMAC,myIP

    # Construccion de la peticion ARP en un solo paso
    frame = ARPHeader + ARPRequestCode + bytes(myMAC) + struct.pack("!I", myIP) + bytes(6) + struct.pack("!I", ip) + bytes(4)

    return frame

'''
    Nombre: createARPReply
    Descripcion: Esta funcion construye una respuesta ARP y devuelve la trama con el contenido.
    Argumentos: 
        -IP: direccion IP a la que contestar
        -MAC: direccion MAC a la que contestar
    Retorno: Bytes con el contenido de la trama de peticion ARP
'''
def createARPReply(IP,MAC):
    global myMAC,myIP

    # Construccion de la respuesta ARP en un solo paso
    frame = ARPHeader + ARPReplyCode + bytes(myMAC) + struct.pack("!I", myIP) + MAC + struct.pack("!I", IP) + byte

    return frame

'''
    Nombre: process_arp_frame
    Descripcion: Esta funcion procesa las tramas ARP. 
        Se ejecutara por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP). 
        Esta funcion debe realizar, al menos, las siguientes tareas:
            -Extraer la cabecera comun de ARP (6 primeros bytes) y comprobar que es correcta
            -Extraer el campo opcode
            -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripcion mas adelante)
            -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripcion mas adelante)
            -Si es otro opcode retornar de la funcion
            -En caso de que no exista retornar
    Argumentos:
        -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso sera None
        -header: cabecera pcap_pktheader
        -data: array de bytes con el contenido de la trama ARP
        -srcMac: MAC origen de la trama Ethernet que se ha recibido
    Retorno: Ninguno
'''
def process_arp_frame(us,header,data,srcMac):


    # Comprobar cabecera correcta
    if ARPHeader != data[0:6]:
        return
    
    # Extraer OPCode
    opcode = data[6:8]

    # OPCode - ARPRequest
    if opcode == ARPRequestCode:
        processARPRequest(data, srcMac)

    # OPCode - ARPReply
    elif opcode == ARPReplyCode:
        processARPReply(data, srcMac)
        
    else:
        return




'''
    Nombre: initARP
    Descripcion: Esta funcion construira inicializara el nivel ARP. Esta funcion debe realizar, al menos, las siguientes tareas:
        -Registrar la funcion del callback process_arp_frame con el Ethertype 0x0806
        -Obtener y almacenar la direccion MAC e IP asociadas a la interfaz especificada
        -Realizar una peticion ARP gratuita y comprobar si la IP propia ya esta asignada. En caso positivo se debe devolver error.
        -Marcar la variable de nivel ARP inicializado a True
'''
def initARP(interface):
    global myIP, myMAC, arpInitialized

    # Registrar process_arp_frame para el ethertype arp (0x0806)
    registerCallback(process_arp_frame, 0x0806)

    # Obtener mac e ip asociadas a la interfaz
    myIP = getIP(interface)
    myMAC = getHwAddr(interface)

    # Comprobar con ARP gratuita si la ip estaba asignada -> dev error
    if ARPResolution(myIP) != None:
        return -1

    # Marcar a True la variable de nivel ARP
    arpInitialized = True

    return 0

'''
    Nombre: ARPResolution
    Descripcion: Esta funcion intenta realizar una resolucion ARP para una IP dada y devuelve la direccion MAC asociada a dicha IP 
        o None en caso de que no haya recibido respuesta. Esta funcion debe realizar, al menos, las siguientes tareas:
            -Comprobar si la IP solicitada existe en la cache:
            -Si esta en cache devolver la informacion de la cache
            -Si no esta en la cache:
                -Construir una peticion ARP llamando a la funcion createARPRequest (descripcion mas adelante)
                -Enviar dicha peticion
                -Comprobar si se ha recibido respuesta o no:
                    -Si no se ha recibido respuesta reenviar la peticion hasta un maximo de 3 veces. Si no se recibe respuesta devolver None
                    -Si se ha recibido respuesta devolver la direccion MAC
        Esta funcion necesitara comunicarse con el la funcion de recepcion (para comprobar si hay respuesta y la respuesta en si) mediante 3 variables globales:
            -awaitingResponse: indica si esta True que se espera respuesta. Si esta a False quiere decir que se ha recibido respuesta
            -requestedIP: contiene la IP por la que se esta preguntando
            -resolvedMAC: contiene la direccion MAC resuelta (en caso de que awaitingResponse) sea False.
        Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
'''
def ARPResolution(ip):
    global requestedIP,awaitingResponse,resolvedMAC
    
    

    # INICIO - CACHE LOCK
    with cacheLock:
        # Si esta en cache devolver la info de cache
        if ip in cache:
            return cache[ip]
    # FIN - CACHE LOCK
    
    # Si no lo esta -> Construir la peticion ARP llamando a createARPRequest
    arprequest = createARPRequest(ip)

    # Enviar dicha peticion
    sendEthernetFrame(arprequest, len(arprequest), [0x0806], broadcastAddr)

    # INICIO - GLOBAL LOCK
    with globalLock:
        awaitingResponse = True
        requestedIP = ip
    # FIN - GLOBAL LOCK

    #Comprobar si hay respuesta o no
    for i in range(3):
        time.sleep(i)
        # INICIO - GLOBAL LOCK
        with globalLock:
            if not awaitingResponse:
                return resolvedMAC
        # FIN - GLOBAL LOCK

    return None
