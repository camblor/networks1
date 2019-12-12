'''
    icmp.py
    Alumno: Alfonso Camblor <alfonso.camblor@estudiante.uam.es>
    2019 EPS-UAM
'''

from ip import *
from threading import Lock
import struct
 
#ICMP
ICMP_PROTO = 1
 
#ICMP_ECHO
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0

#Semaforos
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

    #Caso sin datos 
    if len(data) is 0:
        return
    
    #Calcular checksum
    checksum = chksum(bytes(data))
    #Distinto de 0 -> incorrecto
    if checksum is not 0:
        return

    #Extraccion de campos
    icmp_type = struct.unpack("B", data[0:1])[0]
    code = struct.unpack("B", data[1:2])[0]
    icmp_id = struct.unpack("!H", data[2:4])[0]
    icmp_seqnum = struct.unpack("!H", data[4:6])[0]

    #Logueo
    logging.debug("Tipo: {}".format(icmp_type))
    logging.debug("Codigo: {}".format(code))   


    #Tipo request
    if icmp_type is ICMP_ECHO_REQUEST_TYPE:
        #Envio
        sendICMPMessage(data, ICMP_ECHO_REPLY_TYPE, code, icmp_id, icmp_seqnum, srcIP)
    #Tipo reply
    elif icmp_type is ICMP_ECHO_REPLY_TYPE:
        #Proteccion
        with timeLock:
            icmp_time = icmp_send_times[srcIP]
        #Resta
        icmp_time = time.time() -icmp_time
        print(str(len(data))+" bytes from "+str(struct.pack("!I", srcIP))+": icm_seq="+str(icmp_seqnum)+" ttl= 64 time="+str(icmp_time)+" ns")
        return
    #No hacer nada para otros tipos
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
 
    #Construccion mensaje
    message = bytes()

    #Comparacion tipo request-reply
    if type == ICMP_ECHO_REQUEST_TYPE or type == ICMP_ECHO_REPLY_TYPE:

        #Cabecera
        header = bytes()
        checksum = 0
        header = struct.pack("B", type)+ struct.pack("B", code)+ struct.pack("H", checksum)+struct.pack("!H", icmp_id)+struct.pack("!H", icmp_seqnum)
        
        #Datos al mensaje
        message = bytes(header) + bytes(data)
        if len(message) % 2 is not 0:
            message+=struct.pack("B", 0)

        #Checksum
        checksum = chksum(message)
        header = struct.pack("B", type)+ struct.pack("B", code)+ struct.pack("H", checksum)+ struct.pack("!H", icmp_id)+struct.pack("!H", icmp_seqnum)
        message=header+data
        if len(message) % 2 is not 0:
            message+=struct.pack("B", 0)

        #Comparacion request type
        if type is ICMP_ECHO_REQUEST_TYPE:
            clave = dstIP+icmp_id+icmp_seqnum
            #Proteccion
            with timeLock:
                icmp_send_times[clave] = time.time()

        #Envio y retorno
        sendIPDatagram(dstIP, message, ICMP_PROTO)
        return True
    #Tipo no soportado
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