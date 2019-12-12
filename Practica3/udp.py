'''
    udp.py
    Alumno: Alfonso Camblor <alfonso.camblor@estudiante.uam.es>
    2019 EPS-UAM
'''

from ip import *
import struct
from fcntl import ioctl
import subprocess
 
UDP_HLEN = 8
UDP_PROTO = 17
 

'''
    Nombre: getUDPSourcePort
    Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
    Argumentos:
        -Ninguno
    Retorno: Entero de 16 bits con el número de puerto origen disponible
       
'''
def getUDPSourcePort():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum =  s.getsockname()[1]
    s.close()
    return portNum



'''
    Nombre: process_UDP_datagram
    Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
    un 17 en el campo protocolo de IP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Extraer los campos de la cabecera UDP
        -Loggear (usando logging.debug) los siguientes campos:
            -Puerto origen
            -Puerto destino
            -Datos contenidos en el datagrama UDP

    Argumentos:
        -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: array de bytes con el conenido del datagrama UDP
        -srcIP: dirección IP que ha enviado el datagrama actual.
    Retorno: Ninguno
       
'''
def process_UDP_datagram(us,header,data,srcIP):

 
    sport = struct.unpack("!H",data[0:2])[0]
    dport = struct.unpack("!H",data[2:4])[0]
    lenght = struct.unpack("!H", data[4:6])[0]
 
    logging.debug("Puerto origen : {}".format(sport))
    logging.debug("Puerto destino : {}".format(dport))
    logging.debug("Datos contenidos en el datagrama: {}".format(data[8:lenght]))
    return
 
 
def sendUDPDatagram(data,dstPort,dstIP):
    datagram = struct.pack("!H", getUDPSourcePort()) + struct.pack("!H", dstPort) + struct.pack("!H", 8+len(data)) + struct.pack("!H", 0) + data
 
    if sendIPDatagram(dstIP, datagram, 17) is True:
        return True
    else:
        return False
 
'''
    Nombre: initUDP
    Descripción: Esta función inicializa el nivel UDP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17
    Argumentos:
        -Ninguno
    Retorno: Ninguno
       
'''
def initUDP(): 
    registerIPProtocol(process_UDP_datagram, 17)