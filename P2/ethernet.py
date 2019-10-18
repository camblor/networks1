'''
    ethernet.py
    Implementación del nivel Ethernet y funciones auxiliares para el envío y recepción de tramas Ethernet
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
#Tamaño máximo de una trama Ethernet (para las prácticas)
ETH_FRAME_MAX = 1514
#Tamaño mínimo de una trama Ethernet
ETH_FRAME_MIN = 60
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Diccionario que alamacena para un Ethertype dado qué función de callback se debe ejecutar
upperProtos = {}

def getHwAddr(interface):

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface,0))
    mac =  (s.getsockname()[4])
    s.close()
    return mac


def process_Ethernet_frame(us,header,data):

    global macAddress, upperProtos
    
    #TODO: Implementar aquí el código que procesa una trama Ethernet en recepción

    # Extraer campos de cabecera ethernet
    dirDest = data[:5].hex()
    dirOrig = data[5:11].hex()
    ethertype = data[11:13].hex()

    # Comprobar que la direccion no es ni la nuestra ni la de broadcast
    if dirDest != macAddress and dirDest != broadcastAddr:
        return

    # Comprobar que hay funcion asociada al ethertype
    if ethertype not in upperProtos:
        return

    # Llamar a funcion de nivel superior asociada al ethertype
    upperCallbackFun = upperProtos[ethertype]
    upperCallbackFun(us, header, data, dirOrig)


    
def process_frame(us,header,data):

    threading.Thread(target=process_Ethernet_frame,args=(us,header,data)).start()


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
        #Para la ejecución de pcap_loop
        if handle is not None:
            pcap_breakloop(handle)


def registerCallback(callback_func, ethertype):

    global upperProtos

    # Añadir al diccionario upperProtos: <ethertype, callback_fun>
    upperProtos[ethertype] = callback_func
    

def startEthernetLevel(interface):
   
    global macAddress,handle,levelInitialized,recvThread
    handle = None
    
    # Comprobar nivel Ethernet
    if(levelInitialized):
        return -1

    # Obtener la direccion MAC asociada a la interfaz
    macAddress = getHwAddr(interface)

    # Abrir interfaz especificada
    errbuf = bytearray()
    handle = pcap_open_live(interface, ETH_FRAME_MAX,PROMISC, 100, errbuf)

    # Una vez hemos abierto la interfaz para captura y hemos inicializado las variables 
    # globales (macAddress, handle y levelInitialized) arrancamos el hilo de recepción
    recvThread = rxThread()
    recvThread.daemon = True
    recvThread.start()

    # Todo correcto
    levelInitialized = True
    return 0

def stopEthernetLevel():
    global macAddress,handle,levelInitialized,recvThread

    # Parar el hilo de recepcion de paquetes    
    recvThread.stop()
    # Cerrar la interfaz
    pcap_close(handle)
    # levelInitialized marcado a false
    levelInitialized = False

    return 0

def sendEthernetFrame(data,len,etherType,dstMac):

    global macAddress,handle
    logging.debug('Función no implementada')
    trama = bytearray()

    # Cabecera
    # ---------
    trama.append(dstMac)
    trama.append(macAddress)
    trama.append(etherType)
    # ---------
    # Payload
    # ---------
    trama.append(bytes(data))
    # ---------

    # Rellenar con 0s si es muy pequenia
    if len < ETH_FRAME_MIN:
        trama.append(bytes([0xFF]*(ETH_FRAME_MIN - len)))

    # Devolver error si es muy grande
    elif len > ETH_FRAME_MAX:
        return -1
    
    # pcap_inject retorna el numero de bytes escritos o pcap_error (-1)
    ret = pcap_inject(handle, trama, len)

    # 0 todo correcto, -1 en otro caso
    if ret == -1:
        return ret
    else:
        return 0
    
        