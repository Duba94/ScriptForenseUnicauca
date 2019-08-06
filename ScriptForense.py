#! /usr/bin/env python 
# -*- coding: iso-8859-1 -*-

""" cadena de documentación del módulo """

import os
import os.path
import sys
import requests
from hashlib import md5
from virus_total_apis import PublicApi
from subprocess import Popen, PIPE

nuevaCap="false"
#Funciones de los comandos
def manualvf():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -vf <DirDocumento> <DirArchivo>" )
	print("")	
	print("	<DirDocumento>: Dirección del archivo .txt del hash proporcinado.")
	print("	<DirArchivo>:   Dirección donde se encuentra su archivo de imagen.")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -vf hash.txt /descargas/image.img >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualmw():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -mw <DirArchivo>")
	print("")	
	print("	<DirArchivo>:   Dirección donde se encuentra su archivo de imagen.")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -mw /descargas/image.img >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualas():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -as <DirArchivo>")
	print("")	
	print("	<DirArchivo>:   Dirección donde se encuentra su archivo de imagen.")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -as /descargas/image.img >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualfr():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -fr <tipoformato> <DirDocumento>")
	print("")	
	print("	<tipoformato>:  Formato al que desea convertir la imagen (vmdk, vdi, qcow2).")
	print("	<DirDocumento>: Dirección del archivo que se desea convertir.")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -fr vmdk /descargas/image. >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manuales():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -es <medio>")
	print("")	
	print("<medio>:  medio físico previamente montado, que va ser esterilizado")
	
	print("Para identificar el medio a esterilizar use el comando fdisk -lu")	
	print("")
	print("   Ejemplo: <<#./ScriptForense.py.py -es /dev/sdb >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, dubangarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualrc():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -rc <DirArchivo> <DirDestino>")
	print("")	
	print("	<DirArchivo>: Dirección de la carpeta o imagen del que se desea recuperar los archivos")
	print("	<DirDestino>: Dirección de la carpeta donde se recuperarán los archivos")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -rc ./documents/image ./documents/recuperados. >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualft():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense.py -ft <DirArchivo>")
	print("")	
	print("	<DirArchivo>: Dirección del archivo del que se desea conocer el tipo de formato")
	print("")
	print("   Ejemplo: <<#./ScriptForense.py -ft ./documents/archivo.txt >>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

def manualts():
	print("***************************************************************************")
	print("                           MANUAL                              ")
	print("   Error use sintaxis: ./ScriptForense -ts <DirCaptura>")
	print("")	
	print("	  <DirCaptura>: Dirección de la captura que se desea analizar")
	print("")
	print("   Ejemplo: <<#./ScriptForense -ts ./documents/captura>>")
	print("")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")


def verificar():	
	archivo = open(directorioDocumento,"r")
	aux = archivo.readline()
	aux1 = aux.split()
	hashOrig=aux[0]
	archivo.close()
	print ("\nVerificando hash....")
	resul=os.popen("md5sum "+directorioArchivo).read()
	temp=resul.split()
	hashResul=temp[0]
	print("El hash de la imagen es:"+hashResul)
	print("El hash proporcionado es: "+aux)
	for i in aux1:
		if(i==hashResul):
			print ("Los hash coinciden")
		else:
			print ("Los hash NO coinciden")

def analisis():
	os.system("mkdir /mnt/tmp")
	os.system("fdisk -lu "+directorio)
	start = raw_input("\nIntroduce el valor que se muestra como 'Start': ") 
	print("\nMontando imagen para el análisis.....")
	res=os.system("mount -t ntfs -o loop,ro,offset=$(("+start+"*512)) "+directorio+" /mnt/tmp")
	if(res==0):
		print("\nIniciando análisis.......")
		file = open("./informeForense_logs.txt", "w")
		file.write("\n******************** INFORME FORENSE  ************\n"+ os.linesep)
		
		print("")
		print ("\n>>>Identificando sistema operativo....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/software -p winver").read()
		file.write(">>>>> INFORMACIÓN SISTEMA OPERATIVO:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando nombre de la computadora.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/system -p compname").read()
		file.write(">>>>> INFORMACIÓN NOMBRE DE LA COMPUTADORA:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando el usuario principal de la computadora.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/software -p winnt_cv").read()
		file.write(">>>>> INFORMACIÓN USUARIO PRINCIPAL:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando zona horaria.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/system -p timezone").read()
		file.write(">>>>> INFORMACIÓN ZONA HORARIA:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando dominios.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/software -p winlogon").read()
		file.write(">>>>> INFORMACIÓN DOMINIOS:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando última fecha y hora de apagado.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/system -p shutdown").read()
		file.write(">>>>> ÚLTIMA FECHA Y HORA DE APAGADO:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>Identificando cuentas registradas...\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/SAM -p samparse | grep Username").read()
		file.write(">>>>> INFORMACIÓN CUENTAS REGISTRADAS:"+ os.linesep+resul+ os.linesep)

		print ("\n>>>>>Identificando programas instalados.....\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/software -p uninstall").read()
		file.write(">>>>> INFORMACIÓN PROGRAMAS INSTALADOS :"+os.linesep+resul+ os.linesep)

		print ("\n>>>>Identificando tarjetas de red utilizadas...\n")
		resul=os.popen("perl rip.pl -r /mnt/tmp/WINDOWS/system32/config/software -p networkcards").read()
		file.write(">>>>> INFORMACIÓN TARJETAS DE RED UTILIZADAS:"+ os.linesep+resul+ os.linesep)

		print ("\nFinalizado >> Se ha genarado el reporte: informeForense_logs.txt ")
		file.write("ScriptForense created by:"+ os.linesep)
		file.write("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co"+ os.linesep)
		file.write("   *Universidad del Cauca.")
		file.close()
		os.system("umount /mnt/tmp")
		os.system("rm /mnt/tmp")

	
def convertir():	
	if formt=="vdi":
		rescov=os.system("qemu-img convert -O vdi "+directorio+" conver.vdi")
		if(rescov==0):
			print ("\nConversión exitosa a formato "+formt+".\nNombre del archivo: conver."+formt)
	
	elif formt=="qcow2":
		rescov1=os.system("qemu-img convert -O qcow2 "+directorio+" conver.qcow2")
		if(rescov1==0):
				print ("\nConversión exitosa a formato "+formt+".\nNombre del archivo: conver."+formt)
	elif formt=="vmdk":
		rescov2=os.system("qemu-img convert -O vmdk "+directorio+" conver.vmdk")
		if(rescov2==0):
			print ("\nConversión exitosa a formato "+formt+".\nNombre del archivo: conver."+formt)	
	else:
		print ("Formato no válido")

def recuperar():
	rescov=os.system("foremost -v -t all -i "+directorioArchivo+" -o "+directorioRecuperado+ ">> recuperados.txt")
	if(rescov==0):
		print("Los archivos se guardaron en: "+directorioRecuperado)
		os.system("rm recuperados.txt")
	else:
		print("No fue posible recuperar los archivos, es posible que el directorio "+directorioRecuperado+" ya exista")


def formato():
	res=os.system("file -i "+directorioArchivo+ ">> tipo.txt")
	archivo = open("tipo.txt","r")
	aux = archivo.readline()
	aux1 = aux.split()
	form=aux1[1]
	form1=aux1[2]
	print ("El formato del archivo es: "+form+" "+form1)
	os.system("rm tipo.txt")
	
	

def esterilizar(): 	
	print("Esterilizando la unidad...")
	i=1
	while i <= 3:
		print (i)
		os.system("dd if=/dev/zero of="+medmount+" bs=1024")
		os.system("dd if=/dev/urandom of="+medmount+" bs=1024")
		i+=1

	os.system("dd if=/dev/zero of="+medmount+" bs=1024")
	print("Formateando la unidad...")
	os.system("mkfs.ext2 -c "+medmount)
	name = raw_input("\nDigita el nombre que deseas para la unidad: ") 
	os.system("tune2fs -L "+name+" "+medmount)

def antivirus():
	print ("\nAnalizando archivo...")
	API_KEY = "a14db4f3234ef723522ea66b4f2bbb411ada09b82538eae580f7cbfae5ef7512"
	api = PublicApi(API_KEY)
	with open(directorio, "rb") as f:
		file_hash = md5(f.read()).hexdigest()
	response = api.get_file_report(file_hash)
	if response["response_code"] == 200:
		if response["results"]["positives"] > 0:
			print("Archivo malicioso.")
		else:
			print("Archivo seguro.")
	else:
		print("No ha podido obtenerse el análisis del archivo.")	

def trafico():
	print ("\n------Análisis de tráfico--- ")
	print("\nIniciando análisis.......")
	file = open("./informeTrafico_logs.txt", "w")
	file.write("\n******************** INFORME FORENSE - TRÁFICO DE RED  ************\n"+ os.linesep)

	if(nuevaCap=="true"):
		os.system("tshark -i eth0 -q -w archivo.pcap -a duration:"+duracion)
		resul=os.popen("tshark -Y http.user_agent -Tfields -e http.user_agent -r archivo.pcap").read()
		file.write(">>>>>_INFORMACIÓN USER:"+ os.linesep+resul+ os.linesep)

		resul=os.popen("tshark -Y http.host -Tfields -e http.host -r archivo.pcap | sort -u").read()
		file.write(">>>>>_INFORMACIÓN HOTS:"+ os.linesep+resul+ os.linesep)
	else:		
		resul=os.popen("tshark -Y http.user_agent -Tfields -e http.user_agent -r "+directorio).read()
		file.write(">>>>>_INFORMACIÓN USER:"+ os.linesep+resul+ os.linesep)

		resul=os.popen("tshark -Y http.host -Tfields -e http.host -r "+directorio+" | sort -u").read()
		file.write(">>>>>_INFORMACIÓN HOST:"+ os.linesep+resul+ os.linesep)

	print ("\nFinalizado >> Se ha genarado el reporte: InformeTrafico_logs.txt ")
	file.write("ScriptForense created by:"+ os.linesep)
	file.write("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co"+ os.linesep)
	file.write("   *Universidad del Cauca.")
	file.close()

def ayuda():
	print("***************************************************************************")
	print("                           MANUAL                               ")
	print(" Error use sintaxis: ./ScriptForense.py <Opcion> ó python ./ScriptForense.py")
	print("   <Opciones>")
	print("")	
	print("   	-vf Verifica si el hash de una imagen coincide con el hash escrito en un archivo txt.")
	print("   	-as Analiza la imagen en busca de archivos de configuración.")
	print("   	-fr Convierte un archivo de imagen a formatos como: vmdk, vdi, raw.")
	print("   	-rc Recuperación de archivos borrados de una imagen. ")
	print("   	-ft Verifica el tipo de formato de un archivo. ")
	print("   	-ts Analiza una captura de tráfico de red. ")
	print("   	-mw Analiza una imagen de disco o un archivo en busca de virus.")
	print("   	-es Esteriliza un medio físico.")	
	print("\n")
	print("   Contacto:")
	print("   *lcbuitron@unicauca.edu.co, franmuelas@unicauca.edu.co, fabergarces@unicauca.edu.co")
	print("   *Universidad del Cauca.")
	print("\n***************************************************************************** ")

#Verifica programas instalados
def check_instalados(*progs):
	for prog in progs:
		try:		
			Popen([prog, '--help'], stdout=PIPE, stderr=PIPE)
		except OSError:
			msg= 'El programa {0} es necesario para correr esta funcionalidad'.format(prog)
			sys.exit(msg)
	return true

#Captura de argumentos
tam=len(sys.argv) 
if(tam>1):
	opcion=sys.argv[1]
	#lista de comandos 
	if(opcion=="-vf"):
		if(tam<3):
			manualvf()
		elif(tam>5):
			manualvf()
		else:
			print ("-----Verificación del hash---- ")
			directorioDocumento=sys.argv[2]
			directorioArchivo=sys.argv[3]
			if(os.path.isfile(directorioDocumento) or os.path.isfile(directorioArchivo)):
				verificar()
			else:
				print("Archivo/s inválido/s o inexistente/s, revisa la ayuda <#python ./ScriptForense.py -vf>\n")

	elif(opcion=="-as"):
		if(tam<3):
			manualas()
		elif(tam>4):
			manualas()
		else:
			if(os.path.isfile(sys.argv[2])):
			    if(os.path.isfile("rip.pl") and os.path.isdir("plugins")):
			    	print("Esta opción solo funciona con imagenes que contengan un SO Windows.")
			    	resp = raw_input("\n Está seguro de continuar? (s/n) ")
			    	if(resp=="s"):
			    		print ("-------Análisis de imagen-------")
			    		directorio=sys.argv[2]
			    		analisis()
			    	else:
			    		print("Operación interrumpida ")
			    else:
					print("\nUsted no cuenta con el archivo rip.pl o los plugins de este en ruta del Script\n")
					print("Por favor copie estos archivos de la carpeta donde instaló RegRipper a esta ruta\n")

			else:
				print("Imagen inválida o inexistente, revisa la ayuda <#python ./ScriptForense.py -as>\n")

	elif(opcion=="-es"):
			if(tam<3):
				manuales()
			elif(tam>4):
				manuales()
			else:
				print ("-------Esterilizando unidad física-------")			
				medmount=sys.argv[2]
				esterilizar()

	elif(opcion=="-rc"):
			if(tam<4):
				manualrc()
			elif(tam>4):
				manualrc()
			else:
				print ("Iniciando recuperación de archivos ...")
				directorioArchivo=sys.argv[2]
				directorioRecuperado=sys.argv[3]
				if(os.path.isfile(sys.argv[2])):
					for prog in "foremost":
						try:		
							Popen([prog, '--help'], stdout=PIPE, stderr=PIPE)
						except OSError:
							msg= 'Foremost es necesario para correr esta funcionalidad. \nPuedes usar este comando para iniciar la instalación: apt-get install foremost'.format(prog)
							sys.exit(msg)
					recuperar()
				else:
					print("Archivo inválido o inexistente, revisa la ayuda <#python ./ScriptForense.py -rc>\n")


	elif(opcion=="-ft"):
		if(tam<3):
			manualft()
		elif(tam>3):
			manualft()
		else:
			if(os.path.isfile(sys.argv[2])):
				print ("Verificando el tipo de formato del archivo ...")
				directorioArchivo=sys.argv[2]
				formato()
			else:
					print("Archivo inválido o inexistente, revisa la ayuda <#python ./ScriptForense.py -ft>\n")

	elif(opcion=="-fr"):
		if(tam<3):
			manualfr()
		elif(tam>5):
			manualfr()
		else:
			if(os.path.isfile(sys.argv[3])):
				print ("------Conversión de imagen--- ")
				formt=sys.argv[2]
				directorio=sys.argv[3]
				check_instalados('qemu-img')
				convertir()
			else:
				print("Imagen inválida o inexistente, revisa la ayuda <#python ./ScriptForense.py -fr>\n")

	elif(opcion=="-mw"):
		if(tam<3):
			manualmw()
		elif(tam>4):
			manualmw()
		else:
			if(os.path.isfile(sys.argv[2])):
				print ("------Análisis de virus--- ")
				directorio=sys.argv[2]
				#check_instalados('virustotal')
				antivirus()
			else:
				print("Imagen/archivo inválido o inexistente, revisa la ayuda <#python ./ScriptForense.py -mw>\n")

	elif(opcion=="-ts"):			
		if(tam<3):
			manualts()
		elif(tam>4):
			manualts()
		else:
			if(os.path.isfile(sys.argv[2])):
				directorio=sys.argv[2]
				print("Se ingresó la captura: "+directorio+ "...Pero puedes generar una nueva" )
				resp = raw_input("\n Crear nueva captura? (s/n) ")
				if(resp=="s"):
					nuevaCap="true"
					duracion = raw_input("\n Ingrese el tiempo de captura en segundos:")
				trafico()
			else:
				print("Archivo inválido o inexistente, revisa la ayuda <#python ./ScriptForense.py -ts>\n")
	else:
		
		print("Comando no valido")
		ayuda()
else:
	ayuda()







