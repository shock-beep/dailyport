from django.shortcuts import render,redirect,HttpResponseRedirect,get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from .forms import *
from .models import *
import psutil
import xml.etree.ElementTree as ET
import glob 
def home(request):
    return render(request,"authentication/index.html")

def signup(request):
    # Manobra o request POST
    if request.method == "POST":
        #Recebe o valor dos parametros do post com o nome username e password
        username1 = request.POST.get('username')
        password1 = request.POST.get('password')
        try:
            # cria o utilizador na base de dados
            utilizador = User.objects.create_user(username=username1,password=password1)
        except:
            return HttpResponse('User already created')
        # guarda o utilizador e password na base de dados
        utilizador.save()
        return redirect('signin')
    return render(request,"authentication/signup.html")

def signin(request):
    # Manobra o request POST
    if request.method == 'POST':
        # recebe o valor do username e password e compara se é compativel com o tipo de dados escolhidos
        loginp = LoginForm(request.POST)
        # se for valido em comparação com a form em cima usada
        if loginp.is_valid():
            #obtem utilizador e password só
            nome = loginp.cleaned_data["username"]
            passwd = loginp.cleaned_data["passw"]
            # tenta iniciar uma sessão
            loginn = authenticate(username=nome,password=passwd)
            # se autenticar com sucesso vai para o index.html que vai receber a variavel nome para usar no ficheiro html
            if loginn is not None:
                login(request,loginn)
                print("login function")
                return render(request,'authentication/index.html',{'nome':nome}) 
    # enquanto nao enviar nenhum post mostra a pagina de login
    else:
        
        login_a = LoginForm()
        return render(request,"authentication/signin.html",{"form":login_a})
    # caso erre o login mostra uma pagina a dizer as palavras abaixo
    return HttpResponse('Login Errado')

def signout(request):
    logout(request)
    return redirect("home")


# verificar se é um ipv4 ou nao
def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

import socket
port_list=[]
import datetime
#obter a hora e o dia no momento presente 
current_time = datetime.date.today()

def get_domain_from_ip(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return domain_name
    except socket.herror:
        return None


@login_required
def criar_scan(request):
    #obtem todos os scans já criados
    scan = Scan_DB.objects.all()
    # mostra uma caixa com as opções de velocidade do nmap -T1 -T2 -T3,etc
    velocidades = Op_Scan()
    # mostra as opções do scan de serviços todas as portas, portas ja descobertas e opcionais
    agr=agrserv()
    # se for acionado um post request
    if request.method == 'POST':
        #recebe os valores enviados pelo request
        nome = request.POST.get('nome')
        alvo = request.POST.get('alvo')
        id = request.POST.getlist('choices')
        velo= request.POST.get('velo')
        max_agr = request.POST.get('a')
        pingd = request.POST.get('b')
        port_s=request.POST.get('option')
        portas_op = request.POST.get('portas_op')
        nuclei=False
        fuzzer = False
        dorks=False
        # cria os valores que vai ser colocados no scan para identificar cada um, por exemplo se o booleano web for verdade vai fazer esse scan
        web = False
        port = False
        serv = False
        openvas_s = False
        #tipo de scan
        todas = False
        ja_abertas=False
        op_portas=False
        velocidade=""


        if velo=='t5':
            velocidades='-T5'
        elif velo=='t4':
            velocidades='-T4'
        elif velo=='t3':
            velocidades='-T3'
        elif velo=='t2':
            velocidades='-T2'
        elif velo=='t1':
            velocidades='-T1'
        if max_agr=='on':
            max_agr=True
        else:
            max_agr=False
        if pingd=='on':
            pingd=True
        else:
            pingd=False     
        if port_s=='todas':
            todas=True
        else:
            todas=False

        if port_s == 'descobertas':
            ja_abertas=True
        else:
            ja_abertas=False    
        if port_s == 'portas_op':
            op_portas=True
        else:
            op_portas=False
        for i in id:
            if '1' == i:
                port = True
            elif '2' == i:
                serv= True
            elif '3' in i:
                nuclei=True
                web=True
            elif '4' in i:
                fuzzer=True
            elif '5' in i:
                dorks=True
            
    
        # transforma o dominio para ip 
        try:        
            domain_to_ip = (socket.gethostbyname(alvo))
        except:
            return HttpResponse('Erro ao tentar converter o domain para IP<br> <a href="/scan/">Pagina Inicial</a>')   
        #cria o ip na base de dados
        input = IPAddress.objects.get_or_create(ip=domain_to_ip)
        
        #obtem o ip na base de dados para adicionar valores associadas ao ip
        at = IPAddress.objects.get(ip=domain_to_ip)
        if validate_ip(alvo)==False:
            at.domain=alvo
            at.save()
        else:
            domain = get_domain_from_ip(alvo)
            at.domain=domain
            at.save()

        if ja_abertas==True and at.portas is None:
            return HttpResponse('Impossivel realizar a operação descubra Portos Primeiro <a href="/criar_scan/">Anterior</a>')
        # cria e guarda o scan na base de dados
        scan = Scan_DB(velo_nmap=velocidades,nuclei=nuclei,web_fuzz=fuzzer,dorks=dorks,nome_scan=nome,port_scan=port,serv_scan=serv,web_scan=web,data_inicio=current_time,target=domain_to_ip,comecou=False,max_agressi=max_agr,pingd=pingd,todas=todas,ja_abertas=ja_abertas,op_portas=op_portas,portas_ch=portas_op)
        scan.save()
        return HttpResponseRedirect('.')   
    return render(request,'authentication/criar_scan.html',{"velo":velocidades,"agrserv":agr})

import os
import re

#obtem o caminho para se for mudado o utilizador continua a funcionar
caminho = os.getcwd()
'''
def upload_file():
    nova=[]
    a=get_reports()    
    for one_student_choice in a:
        if one_student_choice not in nova:
            nova.append(one_student_choice)
    for i in nova:
        get_report(i['report_id'],i['task_name'])
'''
'''
def read_csv_to_dict(filename):
    data_list = []
    with open(filename, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip_port_dict = {
                'ip': row['IP'],
                'port': row['Port']  # Convert port to integer if needed
            }
            data_list.append(ip_port_dict)
    0️⃣0️⃣7
    return data_list
'''

def procurar(request):
    portas =[]
    o=[]
    unique_ports=""
    
    ficheiros = os.listdir("{}/output/".format(caminho))
    for i in ficheiros:
        if 'tcp' in i:
           if os.path.getsize("{}/output/{}".format(caminho,i)) > 0:
            f = open("{}/output/{}".format(caminho,i))
            a = f.read()
            lines = a.strip().split('\n')
            ip = lines[0].split(',')[0]
            ports = [line.split(',')[1] for line in lines]
            modified_ports = ['T:' + port for port in ports]
            result = {"ip": ip, "ports": ' , '.join(modified_ports)}            
            ip_address = IPAddress.objects.get_or_create(ip=result['ip'])
            add = IPAddress.objects.get(ip=result['ip'])
            if add.portas==result['ports']:
                add.portas=add.portas
            else:
                add.portas=result['ports']
            add.save()
        '''
        if 'nmap' in i:
            if os.path.getsize("{}/output/{}".format(caminho,i)) > 0:
                servicos=""
                f = open("{}/output/{}".format(caminho,i))
                a = f.read()
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                first_ip_match = re.search(ip_pattern, a)
                if first_ip_match:
                    first_ip = first_ip_match.group()
                pattern = r'(\d+)/tcp'
                matches = re.findall(pattern, a)
                
                unique_ports = list(set(matches))
                unique_ports.sort()
                modified_values = [ 'T:' + str(value) for value in unique_ports]
                
                try:  
                    m=' , '.join(modified_values)
                except:
                    m=""
                try:
                    ip_address = IPAddress.objects.get_or_create(ip=first_ip)
                    asd = IPAddress.objects.get(ip=first_ip)
                    if asd.portas==m:
                        asd.portas=asd.portas
                    else:
                        asd.portas=m
                    asd.save()
                except:
                    pass
                
             '''    
    
    ips = IPAddress.objects.all()
    return render(request, 'authentication/eventos.html', {'a': ips})

def testar(request):
    return HttpResponse('testar')

'''
def get_report(report_id,nome):
    connection = UnixSocketConnection(path='/var/lib/docker/volumes/openvas_gvmd_socket_vol/_data/gvmd.sock')
    
    with Gmp(connection=connection) as gmp:
        gmp.authenticate("admin", "admin")
        tx = gmp.get_report(report_id=report_id,report_format_id=ReportFormatType.CSV_RESULTS,filter_id='f0892777-cb16-4ede-812a-ea8057fb6ae2')
    start_string = "</report_format>"
    end_string = "</report>"
    value = extract_value_between_strings_regex(tx, start_string, end_string)
    decoded = base64.b64decode(value) 
    with open("./csv_results/{}.csv".format(nome), 'wb+') as output_file:
        output_file.write(decoded)
'''
'''
def get_reports():
    reports_id=[]
    connection = UnixSocketConnection(path='/var/lib/docker/volumes/openvas_gvmd_socket_vol/_data/gvmd.sock')
    with Gmp(connection=connection) as gmp:
        gmp.authenticate("admin", "admin")
        ola = gmp.get_reports()
        root = ET.fromstring(ola)
        for report in root.findall('.//report'):
            report_id = report.attrib['id']
            task_name = report.find('task/name').text
            reports_id.append({'report_id': report_id, 'task_name': task_name})
    return reports_id

'''

def http_ou_https():

    return 'ads'

def correr_ferramentas(ferramenta,id):
    scan = Scan_DB.objects.get(id=id)
    portas= IPAddress.objects.get(ip=scan.target)

    # corrigir erro de não verificar todas as portas já abertass
    text = portas.portas
    try:
        cleaned_text = text.replace('T:', '').replace(' ', '')
    except:
        pass
    #

    if scan.max_agressi==True:
        max_str= "--version-all"
    else:
        max_str=""
    if scan.pingd==True:
        pings="-Pn"
    else:
        pings=""
    veloci = scan.velo_nmap

    ffuf_path="tools/ffuf"
    nuclei_path="tools/nuclei"
    tcp_py="tools/tcpscan.py"
    gospider="tools/gospider"
    if ferramenta=='port': 
        process = os.system('python3 {} {} -p all -T 75 -v -o output/output.tcp_{}_{} &'.format(tcp_py,scan.target,scan.target,scan.id))  
        scan.comecou=True    
        scan.save()
    if ferramenta=='nmap':
        if scan.todas==True:
            print("A correr NMAP para todas as portas")
            process = os.system('nmap -p 0-65535 {} {} {} -v -sV > output/output.nmap_{}_{} &'.format(pings,scan.target,veloci,scan.target,scan.id))
            scan.comecou=True
            scan.save()
        if scan.ja_abertas==True:  
            print("A correr NMAP para todas as portas descobertas anteriormente")
            process = os.system('nmap {} -p {} {} -sV -v   > output/output.nmap_{}_{} &'.format(scan.target,cleaned_text,veloci,scan.target,scan.id))
            scan.comecou=True
            scan.save()
        if scan.op_portas==True:
            print("A correr NMAP para todas as portas Opcionais")
            portas = scan.portas_ch
            process = os.system('nmap {} -p {} {} -sV -v > output/output.nmap_{}_{} &'.format(scan.target,portas,veloci,scan.target,scan.id))
            scan.comecou=True
            scan.save()
    if ferramenta=='nuclei':
    
        proc = os.system('{} -target {} > output/output.nuclei_{}_{} &'.format(nuclei_path,scan.target,scan.target,scan.id))
        scan.comecou=True
        scan.save()
    if ferramenta=='fuzz':
        
        proc = os.system('{} -s https://{} -d 1 -u web --robots --sitemap -a  > output/output.fuzz_{}_{} &'.format(gospider,portas.domain,scan.target,scan.id))
        scan.comecou=True
        scan.save()
def comecar(request):
    asd = ""
    if request.method == "POST":
        scan = request.POST.get('id')
        port = request.POST.get('port')
        serv = request.POST.get('serv')
        web = request.POST.get('nuclei')
        fuzz = request.POST.get('fuzz')
        dorks = request.POST.get('dorks')
        if port=='True' and serv=='True' and web=='True'and fuzz=='True':
            asd = "Scan de Portas e Serviços"
            correr_ferramentas('nuclei',scan)
            correr_ferramentas('port',scan)
            correr_ferramentas('nmap',scan)   
            correr_ferramentas('fuzz',scan)          
        elif serv=='True' and port=='False' and web=='False' and fuzz=='True':
            asd = "Scan Serviços"
            correr_ferramentas('nmap',scan)
            correr_ferramentas('fuzz',scan) 
        elif port=='True' and serv=='False' and web=='False' and fuzz=='True':
            asd = "Scan de Portas"
            correr_ferramentas('port',scan)
            correr_ferramentas('fuzz',scan) 
        elif port=='False' and serv=='False' and web=='True' and fuzz=='True':
            asd = "Scan de Portas"
            correr_ferramentas('nuclei',scan)
            correr_ferramentas('fuzz',scan) 
        elif port=='True' and serv=='False' and web=='True' and fuzz=='True':
            asd = "Scan de Portas"
            correr_ferramentas('nuclei',scan)
            correr_ferramentas('port',scan)
            correr_ferramentas('fuzz',scan) 
        elif port=='True' and serv=='True' and web=='False' and fuzz=='True':
            asd = "Scan de Portas"
            correr_ferramentas('port',scan)
            correr_ferramentas('nmap',scan)  
            correr_ferramentas('fuzz',scan) 
        elif port=='False' and serv=='True' and web=='True' and fuzz=='True':
            asd = "Scan de Portas"
            correr_ferramentas('nuclei',scan)
            correr_ferramentas('nmap',scan) 
            correr_ferramentas('fuzz',scan) 
        elif port=='False' and serv=='False' and web=='False' and fuzz=='True':
            correr_ferramentas('fuzz',scan)   
        elif serv=='True' and port=='False' and web=='False' and fuzz=='False':
            asd = "Scan Serviços"
            correr_ferramentas('nmap',scan)
        elif serv=='False' and port=='False' and web=='True' and fuzz=='False':
            asd = "Scan Serviços"
            correr_ferramentas('nuclei',scan)
        elif serv=='True' and port=='True' and web=='False' and fuzz=='False':
            asd = "Scan Serviços"
            correr_ferramentas('port',scan)
            correr_ferramentas('nmap',scan)
    
        return HttpResponseRedirect('nao_comecados')
    return HttpResponse('asd')

def nao_comecados(request):
    scan = Scan_DB.objects.all()
    nome_scans =[]
    scan_nr = []
    target_scan = []
    nuclei=[]
    port=[]
    fuzz = []
    dorks = []
    serv=[]
    for i in scan:
        if i.comecou is False:
            nome_scans.append(i.nome_scan)
            scan_nr.append(i.id)
            target_scan.append(i.target)  
            nuclei.append(i.nuclei)
            fuzz.append(i.web_fuzz)
            dorks.append(i.dorks)
            port.append(i.port_scan)
            serv.append(i.serv_scan)
    a = (nome_scans)
    b = (scan_nr)
    c = (target_scan)
    d = (nuclei)
    e = fuzz
    f = dorks
    x = port
    y = serv
    mylist = zip(a,b,c,d,e,f,x,y)

    return render(request,'authentication/nao_comecados.html',{"lista":mylist})
    

def ver_scan(request):
    scan = Scan_DB.objects.all()
    nome=[]
    target=[]
    ide = []
    data=[]
    mes=[]
    # corre todos os scans criado 
    for i in scan:
        # se o scan a correr coemçou mostra
        if i.comecou is True:
            # variaveis para mostrar no template
            ide.append(i.id)
            nome.append(i.nome_scan)
            target.append(i.target)
            data.append(i.data_inicio)
            mes.append(i.data_inicio)
    a = reversed(nome)
    b = reversed(target)
    c = reversed(ide)
    d = reversed(data)
    e = reversed(mes)
    mylist = zip(a,b,c,d,e)

    return render(request,'authentication/ver_scan.html',{"lista":mylist})



import re

def strip_ansi_codes(s):
    return re.sub(r'\x1b\[(?:\d|;)*[ -/]*[@-~]', '', s)


def unico_scan(request,id):
    scan = Scan_DB.objects.get(id=id)
    port = scan.port_scan
    serv = scan.serv_scan
    web = scan.web_scan
    ip = scan.target
    fuzz = scan.web_fuzz
    dorks = scan.dorks
    aidi = id
    return render(request,'authentication/unico_scan.html',{'port':port,'serv':serv,'web':web,'ip':ip,'id':aidi,'fuzz':fuzz,'dorks':dorks})

def remove_color_codes(text):
    # Define the regex pattern for ANSI escape codes
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    # Substitute the ANSI escape codes with an empty string
    return ansi_escape.sub('', text)

def ver_output_unico(request,ip,tipo,id):
    a=""
    for name in glob.glob('{}/output/output.{}_{}_{}'.format(caminho,tipo,ip,id)): 
        f = open(name,'r')
        a = f.read()
        if tipo=='nuclei':
            a = remove_color_codes(a)
    return render(request,'authentication/ver_output_unico.html',{'contents':a})

def scan(request):
    return render(request,'authentication/scan.html')

def sumario(request):

    return render(request,'authentication/sumario.html')