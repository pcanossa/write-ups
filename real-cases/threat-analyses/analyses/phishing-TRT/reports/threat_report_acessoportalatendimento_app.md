# Relatório de Threat Intelligence – Domínio **acessoportalatendimento.app**

> **Fonte dos dados**: WHOIS (via RDAP), Urlscan.io, VirusTotal, AlienVault OTX, consultas DNS, cURL (tentativa de conexão).  
> **Timestamp da Análise**: 2026-01-09T13:05:18.613737.  

---

## 1. Resumo Executivo
O domínio `acessoportalatendimento.app` foi registrado em 29/04/2025 por um registrante ofuscado (país listado como **Saint Kitts and Nevis**) por meio do registrador **TUCOWS Domains, Inc.**. As zonas de DNS são hospedadas na **Cloudflare** (nameservers `elias.ns.cloudflare.com` e `opal.ns.cloudflare.com`).  

Os servidores de resolução apontam para endereços IP de edge da Cloudflare (ex.: `104.26.8.96`, `104.21.7.199`, `172.67.156.69`). Nenhum dos scanners de reputação (VirusTotal) identificou o domínio como malicioso – todos os 93 engines retornaram **harmless** ou **undetected**. O OTX não possui “pulses” associados.  

Entretanto, vários **sub‑domínios** (`acess200.acessoportalatendimento.app`, `access01.acessoportalatendimento.app`, `acess01.acessoportalatendimento.app`, `acesso2002.acessoportalatendimento.app`, `holmes456.acessoportalatendimento.app`, entre outros) foram submetidos ao **Urlscan.io** e aparecem marcados com a tag *falconsandbox*, indicando que foram analisados em sandboxes e/ou utilizados em testes de análise automática.  

Não há indícios claros de botnet, C2 ou campanhas de phishing diretamente vinculadas ao domínio principal, mas a presença de múltiplos sub‑domínios apontando para IPs de Cloudflare e a inclusão em sandbox‑feeds sugerem que o domínio pode estar sendo usado como **infraestrutura de carga** (hosting, redirecionamento ou entrega de conteúdo) por atores que preferem aproveitar a reputação neutral da camada de CDN.  

Em síntese, o domínio **não é considerado malicioso** pelos principais scanners, mas **exibe sinais de potencial uso em atividades suspeitas** (sandbox‑feeds, sub‑domínios variados). Recomenda‑se tratá‑lo como risco **moderado** e monitorar sua atividade.

---

## 2. Análise de Comportamento

| Fonte | Evidência | Interpretação |
|-------|-----------|----------------|
| **VirusTotal** | 0 malicious, 0 suspicious, 61 harmless, 32 undetected | O domínio ainda não foi marcado como ameaça pelos scanners tradicionais; a ausência de deteções não garante que seja benigno. |
| **Urlscan.io** | 13 variações de sub‑domínios submetidas (ex.: `acess200`, `access01`, `holmes456`). Todas apontam para IPs da Cloudflare (104.x.x.x, 172.67.x.x). | O domínio está sendo usado como ponto de entrega/redirecionamento em sandboxes. A presença de múltiplos sub‑domínios pode indicar **infraestrutura “as‑a‑service”** para diferentes campanhas ou teste automatizado. |
| **AlienVault OTX** | Nenhum pulse encontrado. | Nenhum relato público de campanha conhecida usando o domínio até o momento. |
| **DNS** | Nameservers Cloudflare, sem DNSSEC (delegação não assinada). | O domínio depende de infraestrutura da Cloudflare, que pode mascarar a origem real dos servidores de aplicação. |
| **cURL** | Falha de resolução – “Could not resolve host”. | O domínio só resolve via Cloudflare; pode estar configurado com política de bloqueio de requisições diretas (ex.: “scrape protection”). |
| **Whois/RDAP** | Registrante e contato ofuscados (dados aleatórios), registro recente (2025). | Indicação de uso possivelmente **temporário** ou de “*fast‑flux*”‑style, onde o registrante tenta esconder identidade. |

### Táticas / Técnicas (MITRE ATT&CK) possivelmente associadas
- **T1071 – Application Layer Protocol (HTTP/HTTPS)** – entrega de conteúdo via Cloudflare.
- **T1566.001 – Phishing: Spearphishing Link** – presença em sandboxes pode indicar que URLs foram enviadas em campanhas de phishing.
- **T1105 – Ingress Tool Transfer** – uso de sub‑domínios para hospedagem de arquivos payload.
- **T1568 – Dynamic Resolution** – múltiplos sub‑domínios podem ser gerados dinamicamente para evitar bloqueios estáticos.

> **Nota:** Não há evidência direta de C2, botnet ou ransomware vinculados ao domínio, mas o padrão de uso como “custódia” de URLs suspeitas justifica vigilância.

---

## 3. Informações de Rede e Geográficas

| Campo | Valor |
|-------|-------|
| **Registrar** | TUCOWS Domains, Inc. (ID 69) |
| **Data de registro** | 29 abr 2025 |
| **Data de expiração** | 29 abr 2026 |
| **Nameservers** | `elias.ns.cloudflare.com`, `opal.ns.cloudflare.com` |
| **DNSSEC** | Não assinado (delegação unsigned) |
| **IP(s) de resolução (sub‑domínios observados)** | `104.26.8.96` (Cloudflare – EUA), `104.21.7.199` (Cloudflare – EUA), `172.67.156.69` (Cloudflare – EUA) |
| **ASN** | Diversos (ex.: **AS13335 – Cloudflare, Inc.**) |
| **Provedor (ISP)** | Cloudflare (serviço de CDN/Proxy) |
| **Localização aproximada dos IPs** | United States (principalmente regiões de **California** e **Virginia**, típicas de edge nodes da Cloudflare) |
| **Status WHOIS** | Registrante anônimo/obfuscado; cidade, estado e e‑mail mascarados. |

---

## 4. Domínios e IPs Relacionados

| Tipo | Valor | Observação |
|------|-------|------------|
| **Domínio principal** | `acessoportalatendimento.app` | Registrado em 2025, Cloudflare DNS. |
| **Sub‑domínios (mais frequentes no Urlscan)** | `acess200.acessoportalatendimento.app`<br>`access01.acessoportalatendimento.app`<br>`acess01.acessoportalatendimento.app`<br>`acesso2002.acessoportalatendimento.app`<br>`holmes456.acessoportalatendimento.app`<br>`red08.acessoportalatendimento.app` | Todos apontam para IPs da Cloudflare. |
| **IPs associados** | `104.26.8.96` (Cloudflare)<br>`104.21.7.199` (Cloudflare)<br>`172.67.156.69` (Cloudflare) | Endereços típicos de edge nodes da CDN. |
| **Outros domínios citados nos resultados de sandbox** | Não há domínios externos diretamente associados; apenas sub‑domínios internos. |
| **Hashes / artefatos** | Não há hashes de arquivos listados nos dados fornecidos. |

---

## 5. Recomendações de Ações de Investigação

1. **Monitoramento DNS**  
   - Registre consultas ao domínio `acessoportalatendimento.app` e a todos os sub‑domínios observados nos logs de DNS internos (SIEM, DNS‑firewall).  
   - Crie alertas para resoluções que retornem IPs de Cloudflare fora dos blocos esperados (ex.: mudanças de ASN).  

2. **Análise de Tráfego Web**  
   - Correlacione logs de proxy/NGFW para requisições HTTP(S) ao domínio ou sub‑domínios.  
   - Verifique presença de parâmetros suspeitos (ex.: códigos de download, redirecionamentos).  

3. **Passive DNS / Histórico de Resolução**  
   - Consulte bases de *passive DNS* (RiskIQ, CIRCL) para mapear variações de IP ao longo do tempo e identificar *fast‑flux* ou “domain‑flux”.  

4. **Sandbox / Dynamic Analysis**  
   - Submeta URLs dos sub‑domínios a um sandbox interno (Cuckoo, Falcon) para detectar possíveis payloads (malware, ransomware, scripts).  

5. **Enriquecimento de Inteligência**  
   - Consulte feeds adicionais (MISP, AbuseIPDB, Spamhaus, LookingGlass) para verificar se algum dos IPs listados aparece em relatórios de “malicious infrastructure”.  

6. **Bloqueio de Indicadores (se necessário)**  
   - Caso a organização detecte tráfego indesejado, adicione os IPs da Cloudflare à lista de bloqueio de saída/internas (L7).  
   - Considere bloqueio de nível de domínio (ex.: via DNS sinkhole) apenas se houver evidência de abuso interno.  

7. **Revisão de Certificados TLS**  
   - Embora o domínio não apresente certificado próprio (aponta para Cloudflare), verifique a validade e a cadeia de confiança nos requests capturados — atacantes podem usar certificados legítimos de CDN para mascarar C2.  

8. **Acompanhamento de Inteligência de TTPs**  
   - Mantenha vigilância em feeds de MITRE ATT&CK e em relatórios de phishing (PhishTank, OpenPhish) para detectar novos usos do domínio em campanhas de spear‑phishing ou entrega de payloads.  

---

## 6. Conclusão
O domínio `acessoportalatendimento.app` apresenta **reputação neutra** nos principais scanners, porém o volume de sub‑domínios analisados em sandbox e a dependência de infraestrutura de CDN (Cloudflare) são fatores que podem facilitar o uso por atores maliciosos para **disfarçar infra‑estrutura** (hosting de arquivos, redirecionamento, entrega de links de phishing). Não há evidência direta de comprometimento ou de operação de botnet/C2, mas o cenário recomenda **monitoramento contínuo** e **avaliação baseada em comportamento** dentro do ambiente da organização.  

Trate o domínio como **risco moderado** e implemente os controles de detecção e correlação descritos acima para garantir que qualquer eventual abuso seja identificado e tratado rapidamente.