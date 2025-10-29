# Relatório de Threat Intelligence – Domínio **centralregularizacao.com**

> **Fonte dos dados**: WHOIS.com, URLScan.io, VirusTotal.  
> **Última coleta VirusTotal**: 27‑05‑2025 (timestamp 1758902644).  

---

## 1. Resumo Executivo
O domínio **centralregularizacao.com** foi registrado em **23 / 09 / 2025** via GoDaddy (status “client delete/renew/transfer/update prohibited”) e está apontando para o endereço **216.238.109.50**, um servidor Apache/2.4.58 em Ubuntu hospedado na infraestrutura da **Vultr (AS20473 – “AS‑VULTR, US”)**. O certificado TLS é da Let's Encrypt (válido até 22 / 12 / 2025).  

Nos analisamos o site (URLScan.io) e identificamos que o título da página refere‑se a “Giovani e Adenir Oliveira: da terra ao seu paladar — Blog Veroo Cafés”, conteúdo completamente desvinculado do nome do domínio (que sugere serviços de regularização). O registro foi feito há menos de 1 dia e o URLScan marcou o site como **“suspect”**.  

O **VirusTotal** não encontrou nenhum indício de malware ou de phishing: 0 deteções maliciosas, 34 resultados “undetected” e 61 “harmless”. Não há histórico de reputação, nem listagens em feeds de ameaça conhecidos.  

Em síntese, embora ainda não haja classificação como malicioso, o apontamento de *suspeito* no URLScan, a incongruência entre o nome do domínio e o conteúdo hospedado e a recente criação sugerem que o domínio pode ser usado futuramente como vetor de phishing, hospedagem de conteúdo fraudulento ou campanha de malware.

---

## 2. Análise de Comportamento
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

---

## 3. Informações de Rede e Geográficas
| Campo | Valor |
|-------|-------|
| **ASN** | **AS20473 – AS‑VULTR, US** |
| **ISP / Provedor** | **Vultr Holdings, LLC** (provedor de cloud/VPS) |
| **Localização do IP** | **Estados Unidos – (provavelmente região de data center da Vultr)** |
| **Cidade / Região / País** | Não especificado no WHOIS; geolocalização aponta para **Estados Unidos**. |
| **Endereço IP** | `216.238.109.50` |
| **Nameservers** | `ns33.domaincontrol.com`, `ns34.domaincontrol.com` (GoDaddy) |
| **Data de registro** | 23 / 09 / 2025 (UTC) |
| **Data de expiração** | 23 / 09 / 2026 (UTC) |
| **Status do domínio** | client delete/renew/transfer/update prohibited |

---

## 4. Domínios e IPs Relacionados
| Tipo | Valor | Observação |
|------|-------|------------|
| **IP principal** | `216.238.109.50` | VPS Vultr, PTR: `216.238.109.50.vultrusercontent.com`. |
| **Nameservers** | `ns33.domaincontrol.com` / `ns34.domaincontrol.com` | Servidores de nomes da GoDaddy. |
| **Domínios semelhantes / associados** | Nenhum encontrado nos dados fornecidos. |
| **Outros IPs vistos no scan** | 3 IPs únicos (únicos nas requisições do URLScan), mas apenas o acima listado como A‑record. |

*Recomendação:* Verificar se os outros IPs (capturados nas 28 requisições do URLScan) aparecem em feeds de ameaças ou se são CDN/serviços de terceiros (ex.: Google Analytics, scripts de terceiros).

---

## 5. Recomendações de Investigação
1. **Monitoramento de DNS e WHOIS** – Configurar alertas para alterações de registro, troca de nameserver ou renovação de domínio.  
2. **Vigilância de IP** – Incluir `216.238.109.50` em listas de observação nos SIEM/IDS; consultar feeds como AbuseIPDB, AlienVault OTX, Spamhaus e registrar possíveis futuras denúncias.  
3. **Análise de conteúdo** – Baixar a página completa (HTML, scripts, assets) e submeter a sandbox (e.g., Any.Run, Cuckoo) para detectar comportamentos de download, redirecionamento ou execução de payloads.  
4. **Verificação de URLs externas** – Extrair todos os recursos externos (CDNs, JS, imagens) e checar suas reputações. Muitas vezes, sites suspeitos carregam scripts maliciosos de terceiros.  
5. **Teste de Phishing** – Avaliar a presença de formulários que solicitam credenciais ou informações pessoais; comparar com padrões de phishing (URL encurtado, uso de caracteres Unicode, etc.).  
6. **Correlações de Threat Intel** – Cruzar o domínio e o IP com bases de dados como **CIRCL Passive DNS**, **VirusTotal URL**, **Hybrid Analysis**, **Shodan** e **Censys** para identificar outras aparições ou uso em campanhas anteriores.  
7. **Bloqueio proativo (opcional)** – Caso o seu ambiente seja sensível a phishing, considera‑se a inclusão temporária do domínio/IP em blocklists até que haja clareza sobre seu uso.

---

## 6. Conclusão
- **Risco atual:** **Baixo a moderado** – Não há evidência direta de atividade maliciosa, mas o domínio apresenta indicadores de potencial risco (novo, conteúdo fora de contexto, hospedagem em VPS, tag “suspect” no URLScan).  
- **Probabilidade de abuso futuro:** **Média** – Domínios recém‑criados são frequentemente empregados em campanhas de spam/phishing antes de serem marcados.  
- **Ação recomendada:** **Monitoramento contínuo** e **análise aprofundada de conteúdo**; se o domínio for detectado enviando tráfego suspeito ou solicitando informações confidenciais, deve‑se aplicar bloqueio imediato.

---

*Este relatório foi elaborado com base nas informações disponíveis até a data de coleta. As condições podem mudar rapidamente; recomenda‑se revisitar as fontes de inteligência periodicamente.*  