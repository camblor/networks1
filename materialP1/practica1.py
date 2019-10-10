# -*- coding: utf-8 -*-
'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import datetime
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging
import binascii

ETH_FRAME_MAX = 1514
PAQUETES_TOTAL = 90
PROMISC = 1
NO_PROMISC = 0
TO_MS = 10
num_paquete = 0
TIME_OFFSET = 30*60
BUFSIZ = 100

def signal_handler(nsignal,frame):
	logging.info('Control C pulsado')
	if handle:
		pcap_breakloop(handle)
		

def procesa_paquete(us,header,data):
	global num_paquete, pdumper, num_bytes, debug
	databytes = []
	modification = pcap_pkthdr()
	time = header.ts.tv_sec
	fract = ((header.ts.tv_usec)/1000000)*60

	logging.info('Nuevo paquete de {} bytes capturado a las {}'.format(header.len,datetime.datetime.fromtimestamp(time+fract)))
	num_paquete += 1


	modification.len = header.len
	modification.caplen = header.caplen
	modification.ts.tv_sec = header.ts.tv_sec + TIME_OFFSET
	modification.ts.tv_usec = header.ts.tv_usec

	#Impresion de los N primeros bytes
	#Cambiamos el formato de impresion a hexadecimal con 2 digitos por byte
	if(num_bytes <= header.caplen):
		for value in data[:num_bytes]:
			databytes.append("{:02x}".format(value))

		print("---------------------------")
		print('Primeros ' + str(num_bytes) + ' bytes: ' + str(databytes))
		print("---------------------------\n")
	else:
		for value in data[:header.caplen]:
			databytes.append("{:02x}".format(value))

		print("---------------------------")
		print('Número de bytes del paquete: ' + str(header.caplen) + '\n' + ' bytes: ' + str(databytes))
		print("---------------------------\n")

	#Escribir el tráfico al fichero de captura con el offset temporal
	if pdumper:
		pcap_dump(pdumper,modification,data)
    
	
if __name__ == "__main__":
	global pdumper,args,handle, num_bytes, debug
	debug = False
	parser = argparse.ArgumentParser(description='Captura tráfico de una interfaz ( o lee de fichero) y muestra la longitud y timestamp de los 50 primeros paquetes',
	formatter_class=RawTextHelpFormatter)
	parser.add_argument('--file', dest='tracefile', default=False,help='Fichero pcap a abrir')
	parser.add_argument('--itf', dest='interface', default=False,help='Interfaz a abrir')
	parser.add_argument('--nbytes', dest='nbytes', type=int, default=14,help='Número de bytes a mostrar por paquete')
	parser.add_argument('--debug', dest='debug', default=False, action='store_true',help='Activar Debug messages')
	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(level = logging.DEBUG, format = '[%(asctime)s %(levelname)s]\t%(message)s')
	else:
		logging.basicConfig(level = logging.INFO, format = '[%(asctime)s %(levelname)s]\t%(message)s')

	if args.tracefile is False and args.interface is False:
		logging.error('No se ha especificado interfaz ni fichero')
		parser.print_help()
		sys.exit(-1)

	signal.signal(signal.SIGINT, signal_handler)

	num_bytes = 10
	errbuf = bytearray()
	handle = None
	pdumper = None
	ret = -1
	pkt_data = bytearray()


	'''
	-SITUACION --itf
	-CAPTURA DE INTERFAZ ESPECIFICADA
	'''
	if args.interface:
		#Apertura de la interfaz especificada para captura o la traza (Importante superusuario)
		handle = pcap_open_live(args.interface, BUFSIZ,0, 100, errbuf)

		#Apertura de un dumper para volcar el tráfico (si se ha especificado interfaz)
		descr2 = pcap_open_dead(DLT_EN10MB,1514)
		date  = datetime.datetime.now()
		traza_name = 'captura.' + str(args.interface) + '.' + str(time.time()) + '.pcap'
		pdumper = pcap_dump_open(descr2,traza_name)
		

	'''
	-SITUACION --file
	-LECTURA DE LA TRAZA ESPECIFICADA
	 El programa debe almacenar los paquetes capturados enteros en una traza con nombre captura.nombreitf.FECHA.pcap 
	 (donde FECHA será el tiempo actual UNIX en segundos y nombreitf el nombre de la interfaz especificada).
	'''

	if args.tracefile:
		if(debug == True):
			print("Abriendo archivo " + str(args.tracefile) + "...")
			handle = pcap_open_offline(args.tracefile, errbuf)
			print("Apertura completada...")
		else:
			handle = pcap_open_offline(args.tracefile, errbuf)

	'''
	-SITUACION --nbytes
	-IMPRESION POR PANTALLA DE LOS PRIMEROS nbytes DE CADA PAQUETE
	'''

	if args.nbytes:
		num_bytes = args.nbytes
	
	'''
	-SITUACION --debug
	-IMPRESION DE MENSAJES DEPURACION
	'''
	if args.debug:
		debug = True
	
	#Comienzo del bucle de captura
	if handle:
		if debug == True:
			print("-- Entrando en bucle de captura --\n")
			ret = pcap_loop(handle,PAQUETES_TOTAL,procesa_paquete,None)
			print("-- Saliendo del bucle de captura --\n")
		else:
			ret = pcap_loop(handle,PAQUETES_TOTAL,procesa_paquete,None)

		pcap_close(handle)

	#Casos posibles al ejecutar el bucle de captura (Pred: Error)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))

	#Cerrado del dump
	if pdumper:
		pcap_dump_close(pdumper)	