'''
    icmp.py
    Alumno: Alfonso Camblor <alfonso.camblor@estudiante.uam.es>
    2019 EPS-UAM
'''

from ip import *
from threading import Lock
import struct
 
ICMP_PROTO = 1
 
 
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0
 
timeLock = Lock()
icmp_send_times = {}



'''
    Nombre: process_ICMP_message
    Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
    un 1 en el campo protocolo de IP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Calcular el checksum de ICMP:
            -Si es distinto de 0 el checksum es incorrecto y se deja de procesar el mensaje
        -Extraer campos tipo y código de la cabecera ICMP
        -Loggear (con logging.debug) el valor de tipo y código
        -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
            -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
            los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
            -Enviar el mensaje usando la función sendICMPMessage
        -Si el tipo es ICMP_ECHO_REPLY_TYPE:
            -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
            contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
            -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
            -Mostrar por pantalla la resta. Este valor será una estimación del RTT
        -Si es otro tipo:
            -No hacer nada

    Argumentos:
        -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
        -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
        -data: array de bytes con el conenido del mensaje ICMP
        -srcIP: dirección IP que ha enviado el datagrama actual.
    Retorno: Ninguno
       
'''
def process_ICMP_message(us,header,data,srcIP):

    global icmp_send_times
 
    if len(data) is 0:
        return
    

    #Checksum
    checksum = chksum(bytes(data))
    if checksum is not 0:
        return 

    #Extraccion
    icmp_type = struct.unpack("B", data[0:1])[0]
    code = struct.unpack("B", data[1:2])[0]

    #Debug
    logging.debug("Tipo: {}".format(icmp_type))
    logging.debug("Codigo: {}".format(code))

    #Extraccion
    icmp_id = struct.unpack("!H", data[2:4])[0]
    icmp_seqnum = struct.unpack("!H", data[4:6])[0]

    #Tipo de echo
    if icmp_type is ICMP_ECHO_REQUEST_TYPE:
        sendICMPMessage(data, ICMP_ECHO_REPLY_TYPE, code, icmp_id, icmp_seqnum, srcIP)
    elif icmp_type is ICMP_ECHO_REPLY_TYPE:
        with timeLock:
            icmp_time = icmp_send_times[srcIP]
        icmp_time = time.time() -icmp_time
        print(str(len(data))+" bytes from "+str(struct.pack("!I", srcIP))+": icm_seq="+str(icmp_seqnum)+" ttl= 64 time="+str(icmp_time)+" ns")
        return
             

'''
    Nombre: sendICMPMessage
    Descripción: Esta función construye un mensaje ICMP y lo envía.
    Esta función debe realizar, al menos, las siguientes tareas:
        -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
            -Construir la cabecera ICMP
            -Añadir los datos al mensaje ICMP
            -Calcular el checksum y añadirlo al mensaje donde corresponda
            -Si type es ICMP_ECHO_REQUEST_TYPE
                -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                -Se debe proteger al acceso al diccionario usando la variable timeLock

            -Llamar a sendIPDatagram para enviar el mensaje ICMP
             
        -Si no:
            -Tipo no soportado. Se devuelve False

    Argumentos:
        -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
        -type: valor del campo tipo de ICMP
        -code: valor del campo code de ICMP 
        -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
        -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
        -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
    Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
       
'''
def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):

    global icmp_send_times
 
    message = bytes()
    if type == ICMP_ECHO_REQUEST_TYPE or type == ICMP_ECHO_REPLY_TYPE:
        header = bytes()
        checksum = 0
        header = struct.pack("B", type)+ struct.pack("B", code)+ struct.pack("H", checksum)+struct.pack("!H", icmp_id)+struct.pack("!H", icmp_seqnum)
    
        message = bytes(header) + bytes(data)
        if len(message) % 2 is not 0:
            message+=struct.pack("B", 0)

        checksum = chksum(message)
        header = struct.pack("B", type)+ struct.pack("B", code)+ struct.pack("H", checksum)+ struct.pack("!H", icmp_id)+struct.pack("!H", icmp_seqnum)
        message=header+data
        print(len(message))
        if len(message) % 2 is not 0:
            message+=struct.pack("B", 0)

        
        if type is ICMP_ECHO_REQUEST_TYPE:
            clave = dstIP+icmp_id+icmp_seqnum
            with timeLock:
                icmp_send_times[clave] = time.time()
 
        sendIPDatagram(dstIP, message, ICMP_PROTO)
        return True
    else:
        return False
 
'''
    Nombre: initICMP
    Descripción: Esta función inicializa el nivel ICMP
    Esta función debe realizar, al menos, las siguientes tareas:
        -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

    Argumentos:
        -Ninguno
    Retorno: Ninguno
       
'''                      
def initICMP():

    registerIPProtocol(process_ICMP_message, ICMP_PROTO)