'''
    ethernet.py
    Implementacion del nivel Ethernet y funciones auxiliares para el envio y recepcion de tramas Ethernet
    Autor: Javier Ramos <javier.ramos@uam.es>, Alfonso Camblor <alfonso.camblor@estudiante.uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import logging
import socket
import struct
from binascii import hexlify
import struct 
import threading 
#Tamaño maximo de una trama Ethernet (para las practicas)
ETH_FRAME_MAX = 1514
#Tamaño minimo de una trama Ethernet
ETH_FRAME_MIN = 60
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
#Direccion de difusion (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Diccionario que alamacena para un Ethertype dado que funcion de callback se debe ejecutar
upperProtos = {}
levelInitialized = False

"""
    Nombre: getHwAddr
    Descripcion: Esta funcion obtiene la direccion MAC asociada a una interfaz
    Argumentos:
        -interface: Cadena con el nombre de la interfaz
    Retorno:
        -Direccion MAC de la itnerfaz
"""
def getHwAddr(interface):

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface,0))
    mac =  (s.getsockname()[4])
    s.close()
    return mac

"""
    Nombre: process_Ethernet_frame
    Descripcion: Esta funcion se ejecutara cada vez que llegue una trama Ethernet.
        Esta funcion debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de direccion Ethernet destino, origen y ethertype
            -Comprobar si la direccion destino es la propia o la de broadcast. En caso de que la trama no vaya en difusion o no sea para nuestra interfaz la descartaremos (haciendo un return).
            -Comprobar si existe una funcion de callback de nivel superior asociada al Ethertype de la trama:
                -En caso de que exista, llamar a la funcion de nivel superior con los parametros que corresponde:
                    -us (datos de usuario)
                    -header (cabecera pcap_pktheader)
                    -payload (datos de la trama excluyendo la cabecera Ethernet)
                    -direccion Ethernet origen
                -En caso de que no exista retornar
    Argumentos:
        -us: datos de usuarios pasados desde pcap_loop (en nuestro caso sera None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: bytearray con el contenido de la trama Ethernet
    Retorno:
        -Ninguno
"""
def process_Ethernet_frame(us,header,data):

    # Extraer campos de cabecera ethernet
    dirDest = data[0:6].hex()
    dirOrig = data[6:12].hex()
    ethertype = struct.unpack("!H",data[12:14])[0]

    # Comprobar que la direccion no es ni la nuestra ni la de broadcast
    if dirDest != macAddress and dirDest != broadcastAddr:
        return

    # Comprobar que el ethertype esta como key
    if ethertype in upperProtos.keys():
        upperProtos.get(ethertype)(us, header, data[14:], dirOrig)

    return


"""
    Nombre: process_frame
    Descripcion: Esta funcion se pasa a pcap_loop y se ejecutara cada vez que llegue una trama. La funcion
    ejecutara la funcion process_Ethernet_frame en un hilo nuevo para evitar interbloqueos entre 2 recepciones
    consecutivas de tramas dependientes. Esta funcion NO debe modifciarse
    Argumentos:
        -us: datos de usuarios pasados desde pcap_loop (en nuestro caso sera None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: bytearray con el contenido de la trama Ethernet
    Retorno:
        -Ninguno
"""
def process_frame(us,header,data):
    threading.Thread(target=process_Ethernet_frame,args=(us,header,data)).start()

"""
    Clase que implementa un hilo de recepcion. De esta manera al iniciar el nivel Ethernet
    podemos dejar un hilo con pcap_loop que reciba los paquetes sin bloquear el envio.
    En esta clase NO se debe modificar codigo
"""
class rxThread(threading.Thread): 

    def __init__(self): 
        threading.Thread.__init__(self) 
              
    def run(self): 
        global handle
        #Ejecuta pcap_loop. OJO: handle debe estar inicializado con el resultado de pcap_open_live
        if handle is not None:
            pcap_loop(handle,-1,process_frame,None)
    def stop(self):
        global handle
        #Para la ejecucion de pcap_loop
        if handle is not None:
            pcap_breakloop(handle)

"""
    Nombre: registerCallback
    Descripcion: Esta funcion recibira el nombre de una funcion y su valor de ethertype asociado y añadira en la tabla
        (diccionario) de protocolos de nivel superior el dicha asociacion.
        Este mecanismo nos permite saber a que funcion de nivel superior debemos llamar al recibir una trama de determinado tipo.
        Por ejemplo, podemos registrar una funcion llamada process_IP_datagram asociada al Ethertype 0x0800 y otra llamada process_arp_packet
        asocaida al Ethertype 0x0806.
    Argumentos:
        -callback_fun: funcion de callback a ejecutar cuando se reciba el Ethertype especificado.
            La funcion que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcMac)
            Donde:
                -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor sera siempre None)
                -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                -data: payload de la trama Ethernet. Es decir, la cabecera Ethernet NUNCA se pasa hacia arriba.
                -srcMac: direccion MAC que ha enviado la trama actual.
            La funcion no retornara nada. Si una trama se quiere descartar basta con hacer un return sin valor y dejara de procesarse.
        -ethertype: valor de Ethernetype para el cual se quiere registrar una funcion de callback.
    Retorno: Ninguno
"""
def registerCallback(callback_func, ethertype):

    global upperProtos
    # Añadir al diccionario upperProtos: <ethertype, callback_fun>
    upperProtos[ethertype] = callback_func
    

def startEthernetLevel(interface):
   
    global macAddress,handle,levelInitialized,recvThread
    handle = None
    
    # Comprobar nivel Ethernet
    if levelInitialized:
        return -1

    # Obtener la direccion MAC asociada a la interfaz
    macAddress = getHwAddr(interface)

    # Abrir interfaz especificada
    errbuf = bytearray()
    handle = pcap_open_live(interface, ETH_FRAME_MAX, PROMISC, 100, errbuf)

    # Una vez hemos abierto la interfaz para captura y hemos inicializado las variables 
    # globales (macAddress, handle y levelInitialized) arrancamos el hilo de recepcion
    recvThread = rxThread()
    recvThread.daemon = True
    recvThread.start()

    # Todo correcto
    levelInitialized = (handle != None) and (macAddress != None)
    return 0

'''
    Nombre: stopEthernetLevel
    Descripcion_ Esta funcion parara y liberara todos los recursos necesarios asociados al nivel Ethernet. 
        Esta funcion debe realizar, al menos, las siguientes tareas:
            -Parar el hilo de recepcion de paquetes 
            -Cerrar la interfaz (handle de pcap)
            -Marcar la variable global de nivel incializado a False
    Argumentos: Ninguno
    Retorno: 0 si todo es correcto y -1 en otro caso
'''
def stopEthernetLevel():
    global macAddress,handle,levelInitialized,recvThread

    # Parar el hilo de recepcion de paquetes    
    recvThread.stop()
    # Cerrar la interfaz
    pcap_close(handle)
    # levelInitialized marcado a false
    levelInitialized = False

    return 0

"""
    Nombre: sendEthernetFrame
    Descripcion: Esta funcion construira una trama Ethernet con lo datos recibidos y la enviara por la interfaz de red.
        Esta funcion debe realizar, al menos, las siguientes tareas:
            -Construir la trama Ethernet a enviar (incluyendo cabecera + payload). Los campos propios (por ejemplo la direccion Ethernet origen)
                deben obtenerse de las variables que han sido inicializadas en startEthernetLevel
            -Comprobar los limites de Ethernet. Si la trama es muy pequeña se debe rellenar con 0s mientras que
                si es muy grande se debe devolver error.
            -Llamar a pcap_inject para enviar la trama y comprobar el retorno de dicha llamada. En caso de que haya error notificarlo
    Argumentos:
        -data: datos utiles o payload a encapsular dentro de la trama Ethernet
        -len: longitud de los datos utiles expresada en bytes
        -etherType: valor de tipo Ethernet a incluir en la trama
        -dstMac: Direccion MAC destino a incluir en la trama que se enviara
    Retorno: 0 si todo es correcto, -1 en otro caso
"""
def sendEthernetFrame(data,len,etherType,dstMac):

    global macAddress,handle

    # ---------
    # Cabecera
    # ---------
    trama = dstMac + macAddress + struct.pack("!H", etherType)
    # ---------
    # Payload
    # ---------
    trama += data
    # ---------

    # Rellenar si es muy pequena
    if len(trama) < ETH_FRAME_MIN:
        trama += bytes(ETH_FRAME_MIN-len(trama))

    # Devolver error si es muy grande
    elif len(trama) > ETH_FRAME_MAX:
        return -1
    
    # pcap_inject retorna el numero de bytes escritos o pcap_error (-1)
    ret = pcap_inject(handle, trama, len)

    '''
    pcap_inject devuelve el numero de bytes escritos
    en caso de ejecucion correcta y PCAP_ERROR (-1) 
    en caso contrario.
    '''
    if ret == -1:
        return ret
    else:
        return 0
    
        