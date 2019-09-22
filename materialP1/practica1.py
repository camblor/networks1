# -*- coding: utf-8 -*-
'''
    practica1.py
    Muestra el tiempo de llegada de los primeros 50 paquetes a la interfaz especificada
    como argumento y los vuelca a traza nueva con tiempo actual

    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from rc1_pcap import *
import sys
import binascii
import signal
import argparse
from argparse import RawTextHelpFormatter
import time
import logging

ETH_FRAME_MAX = 1514
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
	global num_paquete, pdumper
	logging.info('Nuevo paquete de {} bytes capturado a las {}.{}'.format(header.len,header.ts.tv_sec,header.ts.tv_sec))
	num_paquete += 1
	#TODO imprimir los N primeros bytes
	#Escribir el tráfico al fichero de captura con el offset temporal
	
if __name__ == "__main__":
	global pdumper,args,handle
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

	errbuf = bytearray()
	handle = None
	pdumper = None
	ret = -1
	h = pcap_pkthdr()
	pkt_data = bytearray()


	'''
	-SITUACION --itf
	-CAPTURA DE INTERFAZ ESPECIFICADA
	
	if True is True:
		#Apertura de la interfaz especificada para captura o la traza (Importante superusuario)
		handle = pcap_open_live(args.interface, BUFSIZ,0, 100, errbuf)

		#Apertura de un dumper para volcar el tráfico (si se ha especificado interfaz)
		descr2 = pcap_open_dead(DLT_EN10MB,1514)
		pdumper = pcap_dump_open(descr2,'salida.pcap')

		#Uso del dump
		pcap_dump(pdumper,h,pkt_data)
		
	'''

	print("Entra en el handle con: " + args.tracefile)

	handle = pcap_open_offline(args.tracefile, errbuf)

	print("HOLALA" + str(args.tracefile))
	
	
	#Comienzo del bucle de captura
	if handle is not None:	
		print("-- Entrando en bucle de captura --\n")
		ret = pcap_loop(handle,50,procesa_paquete,None)
		print("-- Saliendo del bucle de captura --\n")

	#Casos posibles al ejecutar el bucle de captura (Pred: Error)
	if ret == -1:
		logging.error('Error al capturar un paquete')
	elif ret == -2:
		logging.debug('pcap_breakloop() llamado')
	elif ret == 0:
		logging.debug('No mas paquetes o limite superado')
	logging.info('{} paquetes procesados'.format(num_paquete))

	#Cerrado del dump
	if pdumper != None:
		pcap_dump_close(pdumper)	

	

