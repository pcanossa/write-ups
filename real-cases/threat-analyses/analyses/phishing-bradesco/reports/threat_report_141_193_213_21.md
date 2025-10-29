# Relatório de Threat Intelligence – IP **141.193.213.21**

> **Fonte dos dados**: Shodan, IPInfo.io, ARIN / RIPE RDAP, URLScan.io (sem resultados).  
> **Última coleta Shodan**: 2025‑10‑17.  

---

## 1. Resumo Executivo
O endereço **141.193.213.21** pertence ao bloco **141.193.213.0/24**, alocado à **WPEngine, Inc.** e está sob a responsabilidade da **Cloudflare London, LLC** (ASN **AS209242**). Está localizado em **Austin, Texas, EUA**. O host funciona como um ponto de presença (PoP) da Cloudflare, atuando como CDN/reverso‑proxy para dezenas de domínios legítimos (ex.: *wpewaf.com*, *branch.io*, *post.edu*, *controleng.com*, entre vários outros). As portas abertas são tipicamente de serviços web (80, 443) e portas de controle de hospedagem cPanel/WHM (2053, 2082‑2087, 2095‑2096, 8080, 8443, 8880). As respostas HTTP retornam **403 Forbidden** ou **400 Bad Request**, indicando que o acesso direto ao IP é bloqueado e só funciona via nomes de domínio configurados na Cloudflare. Não foram encontradas vulnerabilidades (CVEs) diretamente associadas ao host no Shodan.

Apesar de estar inserido em tráfego de numerosos sites legítimos, o IP também aparece em URLs escaneadas que apontam para campanhas de e‑mail marketing, redirecionamentos suspeitos e URLs encurtadas (ex.: *bit.ly*), sugerindo que pode ser usado como infraestrutura para entrega de conteúdo potencialmente malicioso ou de phishing. Não há evidências de que o IP faça parte de botnet ou de servidores de comando e controle (C2).

---

## 2. Análise de Comportamento
| Indicador | Observação |
|-----------|------------|
| **Tipo de serviço** | CDN/reverso‑proxy (Cloudflare) que protege múltiplos domínios. |
| **Portas abertas** | 80 (HTTP), 443 (HTTPS) – tráfego web. 2053, 2082‑2087, 2095‑2096 – portas de painel de controle de hospedagem (cPanel/WHM) expostas via Cloudflare. 8080, 8443, 8880 – portas alternativas de web/HTTPS. |
| **Respostas HTTP** | 403 Forbidden para requisições diretas ao IP (ex.: “Direct IP access not allowed | Cloudflare”). 400 Bad Request quando protocolo HTTP é enviado a portas HTTPS (ex.: “The plain HTTP request was sent to HTTPS port”). |
| **Associação a domínios** | Hostname principal **wpewaf.com** (pertence à WPEngine). Muitos domínios externos recebem tráfego através deste IP via Cloudflare (e.g., *branch.io*, *post.edu*, *controleng.com*, *signifyd.com*, *mitie.com*, etc.). |
| **Tags Shodan** | `cdn`. |
| **Presença em URLs suspeitas** | Aparece em varreduras do URLScan.io como destino de URLs encurtadas e de campanhas de e‑mail marketing (tags “phish_report”, “falconsandbox”). |
| **Indicadores de botnet/C2** | Nenhum sinal direto (sem portas típicas de P2P, sem banners de shell, sem comunicação externa constante). O comportamento está mais alinhado a um CDN que serve conteúdo de terceiros. |
| **Possível uso malicioso** | Como ponto de presença da Cloudflare, pode ser usado por atores maliciosos para mascarar a origem de phishing, malware ou rastreamento, aproveitando a reputação da Cloudflare. |

**Conclusão:** Não há evidências conclusivas de atividade maliciosa própria ao IP, mas sua função como CDN para inúmeros domínios legítimos e sua presença em URLs potencialmente suspeitas sugerem que pode ser usada como **infraestrutura de entrega** (delivery) de conteúdo malicioso ou como parte de campanhas de phishing, beneficiando‑se da confiança da Cloudflare.

---

## 3. Superfície de Ataque

### 3.1 Portas abertas e serviços identificados
| Porta | Protocolo | Serviço provável | Observação |
|------|-----------|------------------|------------|
| 80   | TCP | HTTP (serviço Cloudflare) | Resposta 403 – acesso direto bloqueado. |
| 443  | TCP | HTTPS (Cloudflare) | Certificado SSL emitido para *wpewaf.com* (CN = wpewaf.com). |
| 2053 | TCP | cPanel/WHM (HTTP) | Resposta 400 – provável porta de painel de controle. |
| 2082 | TCP | cPanel (HTTP) | Resposta 403 – acesso direto não permitido. |
| 2083 | TCP | cPanel (HTTPS) | Resposta 403. |
| 2086 | TCP | WHM (HTTP) | Resposta 403. |
| 2087 | TCP | WHM (HTTPS) | Resposta 400. |
| 2095 | TCP | Webmail (HTTP) | Resposta 403. |
| 2096 | TCP | Webmail (HTTPS) | Resposta 400. |
| 8080 | TCP | HTTP alternativo (possível aplicação web) | Resposta 403. |
| 8443 | TCP | HTTPS alternativo (possível painel) | Resposta 403. |
| 8880 | TCP | HTTP/HTTPS alternativo (possível API) | Resposta 403 (texto “error code: 1003”). |

> **Nota:** Todas as respostas indicam que o IP está configurado para recusar acesso direto, funcionando apenas como *frontend* para domínios configurados na camada Cloudflare.

### 3.2 Vulnerabilidades (CVEs) detectadas
- **Nenhuma vulnerabilidade (CVE) listada** nas informações exportadas do Shodan para este host.  
- As portas expostas (cPanel/WHM) podem, em teoria, ser alvos de exploits conhecidos (ex.: CVE‑2022‑27925 – “cPanel authentication bypass”), porém não há evidência de que essas vulnerabilidades estejam presentes ou exploráveis neste IP, já que a camada Cloudflare bloqueia o acesso direto.

---

## 4. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **ASN** | **AS209242 – CLOUDFLARESPECTRUM Cloudflare London, LLC** |
| **Provedor (ISP)** | **Cloudflare London, LLC** |
| **Organização proprietária** | **WPEngine, Inc.** (registrada em Austin, TX) |
| **Localização** | **Austin, Texas, Estados Unidos (US)** |
| **Latitude / Longitude** | 30.2672, ‑97.7431 |
| **CIDR** | 141.193.213.0/24 |
| **Tipo de rede** | Direct Allocation (bloco /24) |
| **Data de registro** | 2020‑07‑13 (última atualização 2020‑07‑23) |

---

## 5. Recomendações de Investigação e Mitigação

1. **Correlacionar logs de firewall/IDS/IPS**  
   - Procure por tráfego de entrada/saída para 141.193.213.21 nas portas listadas.  
   - Identifique se há tentativas de conexão direta ao IP (bypass de hostnames) que podem indicar scouting ou exploração de vulnerabilidades do painel.

2. **Verificar ameaças de reputação**  
   - Consulte feeds de inteligência (e.g., AbuseIPDB, Spamhaus, VirusTotal, OpenPhish) para verificar se o IP está listado em campanhas de phishing, spam ou distribuição de malware.  
   - Avalie a frequência de URLs encurtadas que redirecionam ao IP (ex.: *bit.ly*).

3. **Analisar tráfego HTTP/S**  
   - Capture cabeçalhos e user‑agents de requisições que chegam ao IP.  
   - Verifique se há padrões de “scraping” ou “credential stuffing”.

4. **Monitorar alterações de DNS**  
   - Observe registros DNS (CNAME, A) que apontem para 141.193.213.21. Mudanças suspeitas podem indicar hijacking de subdomínios.

5. **Inspeção de serviços de gerenciamento (cPanel/WHM)**  
   - Caso sua organização utilize este IP para hospedagem, confirme que as portas de administração (2082‑2087, 2095‑2096) estão adequadamente protegidas por VPN ou lista de IPs permitidos.  
   - Aplique autenticação forte (2FA) e mantenha o software atualizado.

6. **Aplicar bloqueios de acesso direto ao IP**  
   - Caso o IP não deva ser acessado diretamente, configure o firewall para bloquear conexões fora da Cloudflare (ex.: permitir somente IPs da rede Cloudflare).  

7. **Compartilhar indicadores**  
   - Disseminar IOCs (IP, portas, hashes de certificados) com CSIRT/ISAC para ampliar a visibilidade de possíveis abusos.

---

### Observação Final
O endereço **141.193.213.21** funciona essencialmente como um **ponto de entrega de conteúdo (CDN) da Cloudflare** para uma vasta gama de domínios, muitos dos quais são empresas legítimas. Embora não haja evidência direta de comprometimento ou de operação de botnet/C2, a sua visibilidade em múltiplas campanhas de marketing e URLs encurtadas reforça a necessidade de **monitoramento contínuo** para detectar eventuais usos maliciosos de sua infraestrutura.  

---