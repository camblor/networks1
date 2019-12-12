'''
    ip.py
    Alumno: Alfonso Camblor <alfonso.camblor@estudiante.uam.es>
    2019 EPS-UAM
'''

from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
import struct
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b
#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Valor inicial para el IPID
IPID = 0
#Valor de ToS por defecto
DEFAULT_TOS = 0
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Valor de TTL por defecto
DEFAULT_TTL = 64


'''
    Nombre: chksum
    Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
    Argumentos:
        -msg: array de bytes con el contenido sobre el que se calculará el checksum
    Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
'''
def chksum(msg):

    s = 0      
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i] 
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    s = s + (s >> 16)
    s = ~s & 0xffff
 
    return s


'''
    Nombre: getMTU
    Descripción: Esta función obteiene la MTU para un interfaz dada
    Argumentos:
        -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
    Retorno: Entero con el valor de la MTU para la interfaz especificada
'''
def getMTU(interface):

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]
    
    s.close()
    
    return mtu


'''
    Nombre: getNetmask
    Descripción: Esta función obteiene la máscara de red asignada a una interfaz 
    Argumentos:
        -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
    Retorno: Entero de 32 bits con el valor de la máscara de red
''' 
def getNetmask(interface):

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]
 
'''
    Nombre: getDefaultGW
    Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
    Argumentos:
        -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
    Retorno: Entero de 32 bits con la IP del gateway
'''
def getDefaultGW(interface):

    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
     
    return struct.unpack('!I',socket.inet_aton(dfw))[0]
 
 
'''
    Nombre: process_IP_datagram
    Descripción: Esta función procesa datagramas IP recibidos.
        Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
            -Calcular el checksum sobre los bytes de la cabecera IP
                -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
            -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
            -Loggear (usando logging.debug) el valor de los siguientes campos:
                -Longitud de la cabecera IP
                -IPID
                -Valor de las banderas DF y MF
                -Valor de offset
                -IP origen y destino
                -Protocolo
            -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
            clave el valor del campo protocolo del datagrama IP.
                -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha funciñón 
                pasando los datos (payload) contenidos en el datagrama IP.
     
    Argumentos:
        -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
        -header: cabecera pcap_pktheader
        -data: array de bytes con el contenido del datagrama IP
        -srcMac: MAC origen de la trama Ethernet que se ha recibido
    Retorno: Ninguno
'''
def process_IP_datagram(us,header,data,srcMac):

 
    #Extraccion
    IPOrigen = struct.unpack("!I", data[12:16])[0]
     
    IPDestino = struct.unpack("!I", data[16:20])[0]
    
    IPID = struct.unpack("!H", data[4:6])[0]
    protocolo = struct.unpack("B", data[9:10])[0]
    primerByte = struct.unpack("B", data[0:1])[0]
    
    #Longitud de cabecera
    IHL = primerByte & 0x0F
    
    #Banderas
    BanderasOffset = struct.unpack("!H", data[6:8])[0]
    offset = BanderasOffset & 0X1FFF
    DF = (BanderasOffset >> 14) & 0x0001
    MF = (BanderasOffset >> 13) & 0x0001


    #Checksum
    datagram_header = data[0:IHL*4]
    checksum = chksum(datagram_header)

    
    #Logging
    logging.debug("Longitud de cabecera : {}".format(IHL*4))
    logging.debug("IPID : {}".format(IPID))
    logging.debug("DF : {}  MF: {}".format(DF, MF))
    logging.debug("OFFSET : {}".format(offset))
    logging.debug("IP Origen : {}".format(bytes(data[12:16])))
    logging.debug("IP Destino : {}".format(bytes(data[16:20])))
    logging.debug("Protocolo : {}".format(protocolo))
    logging.debug("CHECKSUM: {}".format(checksum))
    
    #Checksum debe ser 0
    if checksum is not 0:
        return
    
    #Protocols tiene registrada la funcion
    if protocolo in protocols:
        funct = protocols[protocolo]
        funct(us,header, data[IHL*4:], IPOrigen)
    else:
        return
           

'''
    Nombre: registerIPProtocol
    Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla 
        (diccionario) de protocolos de nivel superior dicha asociación. 
        Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un 
        determinado valor del campo protocolo (por ejemplo TCP o UDP).
        Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra 
        llamada process_ICMP_message asocaida al valor de protocolo 1. 
    Argumentos:
        -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado. 
            La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
            Dónde:
                -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                -srcIP: dirección IP que ha enviado el datagrama actual.
            La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
        -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
    Retorno: Ninguno 
'''   
def registerIPProtocol(callback,protocol):

    global protocols
    #Asociacion
    protocols[protocol] = callback
     


'''
    Nombre: initIP
    Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
        -Llamar a initARP para inicializar el nivel ARP
        -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
            -IP propia
            -MTU
            -Máscara de red (netmask)
            -Gateway por defecto
        -Almacenar el valor de opts en la variable global ipOpts
        -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
    Argumentos:
        -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
        -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
    Retorno: True o False en función de si se ha inicializado el nivel o no
'''
def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW,ipOpts

    
    #Inicializar ARP
    if initARP(interface) == False:
        return False;
    
    #Obtencion
    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)
    ipOpts = opts
 
    #Registramos a nivel ethernet
    registerCallback(process_IP_datagram, bytes([0x08, 0x00]))
 
    return True


'''
    Nombre: sendIPDatagram
    Descripción: Esta función construye un datagrama IP y lo envía. 
    En caso de que los datos a enviar sean muy grandes la función
    debe generar y enviar el número de fragmentos IP que sean necesarios.
    Esta función debe realizar, al menos, las siguientes tareas:
        -Determinar si se debe fragmentar o no y calcular el número de fragmentos
        -Para cada datagrama o fragmento:
            -Construir la cabecera IP con los valores que corresponda.
                Incluir opciones en caso de que ipOpts sea distinto de None
            -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
            -Añadir los datos a la cabecera IP
            -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
            -Enviar el datagrama o fragmento llamando a sendEthernetFrame. 
                Para determinar la dirección MAC de destino al enviar los datagramas:
                -Si la dirección IP destino está en mi subred:
                    -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                -Si la dirección IP destino NO está en mi subred:
                    -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
        -Para cada datagrama (no fragmento):
            -Incrementar la variable IPID en 1.
    Argumentos:
        -dstIP: entero de 32 bits con la IP destino del datagrama 
        -data: array de bytes con los datos a incluir como payload en el datagrama
        -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
        contenidos en el payload. Por ejemplo 1, 6 o 17.
    Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
       
'''
def sendIPDatagram(dstIP,data,protocol):
    global IPID, ipOpts, myIP, MTU, defaultGW

    #Header e IHL
    header = bytes()
    IHL = 20
  
    #ipOpts
    if ipOpts is not None:
        IHL += len(ipOpts)
    
    IHL //= 4
    IHL = int(IHL)
     

    #Protocolo
    version = 4
    version = (version | (1<<6)) & 0xF0
    byte1 = int(version +IHL)
    type_service = 0
    totalLen = IHL*4+ len(data)
    dstMac = ARPResolution(dstIP) 
 

    #Caso dstMac none (default GW)
    if dstMac is None:
        dstMac = ARPResolution(defaultGW)

    
    #Inicializacion
    flags_offset = 0 
    checksum = 0
    
    #Construccion cabecera
    header += struct.pack("B", byte1) + struct.pack("B", 0) + struct.pack("!H", totalLen) + struct.pack("!H", IPID) + struct.pack("!H", flags_offset) + struct.pack("B", DEFAULT_TTL) + struct.pack("B", protocol) + struct.pack("!H", checksum) + struct.pack("!I", myIP) + struct.pack("!I", dstIP)
    if ipOpts is not None:
        header += ipOpts
    
    #calculamos el checksum
    checksum = struct.pack("H", chksum(header))
     
     #completamos cabecera con checksum e ipOpts (si no es None)
    
    #Fragmentacion
    if len(data) > MTU:
        #Numero de bytes maximos y numero de fragmentos
        maximo = MTU-IHL*4
        nfragmentos = len(data)/maximo

        i=0        
        while(i<nfragmentos):
            #Indices del fragmento
            k=maximo*i
            l=k+maximo 

            #Fragmento y datos restantes
            datos = data[k:l]
            restante = len(data) - k

            #Caso ultimo datagrama a enviar
            if restante <= maximo:
                flags = 0
                offset = int(k/8)
                flags_offset = flags | offset
                totalLen = restante + IHL*4

            #Caso datagrama no es el ultimo a enviar
            else:
                flags = 0
                flags = flags|(1<<13)
                offset = int(k/8)
                flags_offset = flags | offset
                totalLen = maximo + IHL*4 #longitud del datagrama entero
            
            checksum = struct.pack("!H", 0)


            #ipOpts
            if ipOpts is not None:
                header = struct.pack('B', byte1) + struct.pack("B", 0) 
                header += struct.pack('!H', totalLen) +  struct.pack('!H', IPID) 
                header += struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL)
                header += struct.pack('B', protocol) + checksum + struct.pack('!I', myIP)
                header += struct.pack('!I', dstIP) + ipOpts 
                checksum = chksum(header)
                header = struct.pack('B', byte1) + struct.pack("B", 0) 
                header += struct.pack('!H', totalLen) +  struct.pack('!H', IPID) 
                header += struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL) 
                header += struct.pack('B', protocol) + struct.pack("!H", checksum) + struct.pack('!I', myIP) 
                header += struct.pack('!I', dstIP) + ipOpts
            #No ipOpts
            else:
                header = struct.pack('B', byte1) + struct.pack("B", 0) + struct.pack('!H', totalLen) +  struct.pack('!H', IPID) + struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL) + struct.pack('B', protocol) + checksum + struct.pack('!I', myIP) + struct.pack('!I', dstIP)
                checksum = chksum(header)
                header = struct.pack('B', byte1) + struct.pack("B", 0) + struct.pack('!H', totalLen) +  struct.pack('!H', IPID) + struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL) + struct.pack('B', protocol) + struct.pack("!H", checksum) + struct.pack('!I', myIP) + struct.pack('!I', dstIP)

            #Preparacion para envio
            datagrama = header+datos
            length = len(datagrama)
            
            #Envio
            if sendEthernetFrame(datagrama, length, bytes([0x08, 0x00]), bytes(dstMac)) is -1:
                return False
            i+=1
            
        #Aumento de contador tras enviar fragmentos
        IPID+=1
        return True


    else:
        #ipOpts
        if ipOpts is not None:
            header = struct.pack('B', byte1) + struct.pack("B", 0) + struct.pack('!H', totalLen) +  struct.pack('!H', IPID) + struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL) + struct.pack('B', protocol) + checksum + struct.pack('!I', myIP) + struct.pack('!I', dstIP) + ipOpts 
        else:
            header = struct.pack('B', byte1) + struct.pack("B", 0) + struct.pack('!H', totalLen) +  struct.pack('!H', IPID) + struct.pack('!H', flags_offset) + struct.pack('B', DEFAULT_TTL) + struct.pack('B', protocol) + checksum + struct.pack('!I', myIP) + struct.pack('!I', dstIP)
    
        #Preparacion para envio
        datagrama = header + data
        length = len(datagrama)


        #Envio     
        if sendEthernetFrame(datagrama, length, bytes([0x08, 0x00]), bytes(dstMac)) is -1:
            return False
        
        #Aumento de contador
        IPID += 1
        return True

