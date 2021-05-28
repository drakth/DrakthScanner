import sys
import socket
import fcntl
import struct
import json
import requests
import subprocess

# Cantidad de argumentos que le llegan al programa.
cantParametros = len(sys.argv)
#print("Cantidad parametros: " + str(cantParametros))

datosJSON = {}
 
# Nombre del script python.
#print("\nScript:", sys.argv[0])

#Los puertos que vamos a scanear...
puertos = [4, 20, 21, 22, 25, 53, 79, 80, 110, 111, 443, 8080, 9050, 20001, 26810]

#No se como funciona esto pero el dios google dice que anda.
def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

#Robado de stack overflow, obtiene el service name.
def getServiceName(port, proto):
        try:
            name = socket.getservbyport(int(port), proto)
        except:
            return None
        return name

print("*******************************************************")
print("***       Drakth Scanner - Basic port scan          ***")
print("***       Parameters:                               ***")
print("***         -i [Interfaz]                           ***")
print("***         -h [IP]                                 ***")
print("***         -t (Only TCP)                           ***")
print("***         -u (Only UDP)                           ***")
print("*******************************************************")

ipEspecifica = 0
soloTCP = 0
soloUDP = 0
archivoTexto = ""

#Si solo ingresaron 1 o 2 argumentos salimos con error.
if cantParametros == 1 or cantParametros == 2:
    print("Parametros insuficientes.")
    exit(-1)

#loopeamos los argumentos para determinar como se esta ejecutando
for i in range(1, cantParametros):
    argumento = sys.argv[i]

    if argumento == "-i":
        inter = sys.argv[i+1]
    elif argumento == "-h":
        target = sys.argv[i+1]
        ipEspecifica = 1
    elif argumento == "-t":
        soloTCP = 1
    elif argumento == "-u":
        soloUDP = 1

#Lo pasamos a bytes y obtenemos la IP, en base a esa IP haremos
#el scan.
if ipEspecifica == 0:
    intf_b = inter.encode()

try:
    if ipEspecifica == 0:
        ipLocal = get_ip_address(intf_b)
    else:
        ipLocal = target #No seria (O si) una IP local pero no quiero cambiar el nombre de la variable.
except Exception as inst:
    print(type(inst))    # La excepcion
    print(inst.args)     # Argumentos
    print(inst)          # Mensaje
    exit(-1)

#Separamos la IP para quedarnos con los primeros 3 octetos.
IP = ipLocal.split('.')
IP_RANGE = str(IP[0]) + '.' + str(IP[1]) + '.' + str(IP[2])

datosJSON = {}
datosJSON['SCAN'] = []

#Unificamos las dos porquerias.... (TCP / UDP)
for host in range(1, 255):
#for host in range(110, 112):
#for host in range(240, 242):
    print("IP " + IP_RANGE + "." + str(host))
    print("=============================")
    archivoTexto = archivoTexto + "IP " + IP_RANGE + "." + str(host) + "\n"
    archivoTexto = archivoTexto + "============================="  + "\n"

    for puerto in puertos:
        try:
            #SOCK_STREAM = TCP
            #SOCK_DGRAM = UDP

            if soloUDP == 0:
                #Intentamos conectarnos...
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((IP_RANGE + "." + str(host), puerto))
                banner = s.recv(1024)
                info = str(banner)

                print("\t\tTCP:")
                archivoTexto = archivoTexto + "\t\tTCP:\n"

                print("\t\t\t\t" + str(puerto) + ":\t" + info)
                archivoTexto = archivoTexto + "\t\t\t\t" + str(puerto) + ":\t" + info + "\n"
                
                datosJSON['SCAN'].append({
                    'Puerto':str(puerto),
                    'Protocolo':'TCP',
                    'Banner':str(info)
                })

                s.close()
        except Exception as inst:
            #print(type(inst))    # the exception instance
            #print(inst.args)     # arguments stored in .args
            #print(inst)          # __str__ allows args to be printed directly,
                                 # but may be overridden in exception subclasses
            #x, y = inst.args     # unpack args  
            #print('x =', x)
            #print('y =', y)
            s.close()
            pass
            #Esto no me funciono para UDP o hice algo mal.
            #s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            #client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            #s2.settimeout(1)
            #s.connect((IP_RANGE + "." + str(host), puerto))
            #banner2 = s2.recv(1024)
            #info2 = str(banner2)

            #print("\t\tUDP:")

            #print("\t\t\t\t" + str(puerto) + ":\t" + info)

            #datosJSON['SCAN'].append({
            #    'Puerto':str(puerto),
            #    'Protocolo':'UDP',
            #    'Banner':str(info2)
            #})
# UDP:
            if soloTCP == 0:
                MESSAGE = "ping"
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                if client == -1:
                    print("Fallo la creacion del socket UDP.")
                sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                if sock1 == -1:
                    print("Fallo la creacion del socket ICMP.")
                try:
                    #Intentamos conectarnos y vemos si obtenemos una respuesta...
                    #Como UDP no es orientado a conexiones puede ser que nunca no respondan...
                    client.sendto(MESSAGE.encode('utf_8'), (IP_RANGE + "." + str(host), puerto))
                    sock1.settimeout(1)
                    data, addr = sock1.recvfrom(1024)
                    #data_hex = data.hex()
                    data_info = str(data)
                    data_addr = str(addr)
                    #print("Data: " + data_info)
                    #print("addr: " + data_addr)
                    #print("\t\tUDP:")

                    #print("\t\t\t\t" + str(puerto) + ":\t" + data_info)
                except socket.timeout:
                    #Intentamos obtener que tipo de servicio es...
                    serv = getServiceName(puerto, 'udp')
                    if not serv:
                        #No encontramos nada...
                        pass
                    else:
                        #Encontramos algo...
                        print("\t\tUDP:")
                        archivoTexto = archivoTexto + "\t\tUDP:\n"
                        #print("\t\t\t\t" + str(puerto) + ":\t" + data_info)
                        print("\t\t\t\t" + str(puerto) + ":\t" + serv)
                        archivoTexto = archivoTexto + "\t\t\t\t" + str(puerto) + ":\t" + serv + "\n"

                        datosJSON['SCAN'].append({
                            'Puerto':str(puerto),
                            'Protocolo':'UDP',
                            'Banner':str(serv)
                        })
                        #print('Port {}:      Open'.format(puerto))
                except socket.error as sock_err:
                    if (sock_err.errno == socket.errno.ECONNREFUSED):
                        print('Connection refused')
                        pass
                except:
                    pass
                client.close()
                sock1.close()
# FIN UDP 

#Grabamos el json e intentamos hacer el post. (Que fallara)
with open('data.json', 'w') as outfile:
    json.dump(datosJSON, outfile)

#Me lo guardo tambien como txt porque me gusta mas
f = open("data.txt", "w")
f.write(archivoTexto)
f.close()

try:
    req = requests.post('http://127.0.0.1/example/fake_url.php', json=datosJSON)
    status = req.status_code
except Exception as inst:
    print("Ocurrio un error en el POST de los datos.")
    #print(type(inst))    # the exception instance
    #print(inst.args)     # arguments stored in .args
    #print(inst)          # __str__ allows args to be printed directly,

print("Fin de la ejecucion.")